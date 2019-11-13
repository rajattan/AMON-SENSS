#include <signal.h>
#include <iostream>
#include <algorithm>
#include <fstream>
#include <sched.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <sys/poll.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/ethernet.h>
#include <sys/time.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <monetary.h>
#include <locale.h>
#include <regex.h>
#include <iostream>
#include <sstream>
#include <string>
#include <map>
#include <cmath>
#include <iomanip>

#include <dirent.h>

#include "utils.h"
#include "haship.h"
#include "haship.c"

using namespace std;

map<int, float> protocolCount;
map<unsigned int, float> dstIPCount;
map<int, float> dstPortCount;
map<int, float> ppsCount;
map<int, float> bpsCount;

map<int, float> protocolMap;
map<unsigned int, float> dstIPMap;
map<int, float> dstPortMap;
map<int, float> ppsMap;
map<int, float> bpsMap;
int ctr = 0;

multimap<unsigned int, unsigned int> constraintMap;

// We store delimiters in this array
//int* delimiters;

// Something like strtok but it doesn't create new
// strings. Instead it replaces delimiters with 0
// in the original string
void parse(char* input, char delimiter, int** array)
{
  int pos = 0;
  memset(*array, 255, AR_LEN);
  int len = strlen(input);
  for(int i = 0; i<len; i++)
    {
      if (input[i] == delimiter)
	{
	  (*array)[pos] = i+1;
	  input[i] = 0;
	  pos++;
	}
    }
}

// Variables/structs needed for detection
int verbose = 0;

long firsttime = 0;       // Beginning of trace 
long freshtime = 0;       // Where we last ended when processing data 
long firsttimeinfile = 0; // First time in the current file 
long updatetime = 0;      // Time of last stats update
long statstime = 0;       // Time when we move the stats to history 
char filename[MAXLINE];   // A string to hold filenames

// Serialize access to statistics
pthread_mutex_t cells_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t flows_lock = PTHREAD_MUTEX_INITIALIZER;

// Types of statistics. If this changes, update the entire section 
u_int32_t T1_16[65536];
u_int32_t T2_16[65536];
u_int32_t T3_17[131072];	     /*2^17-long array */
int IDX[Low14];
int IDX17[131072];		     /*2^17-long array */
int STRATA_IDX17_prefix_bin[131072]; /*2^17-long array */
int seed = 134;
u_int32_t IP_prefix = 0;
int* delimiters;

// Parameters from as.config
map<string,double> parms;
int SIZE = 28910;
//unsigned int arr[28910][128][128];
//unsigned int arp[28910][128][128];
//long first_flow = 1519053741;

// Trim strings 
//


#include <chrono>

void amonProcessing(flow_t flow, int len, long start, long end, int oci)
{
  pthread_mutex_lock (&flows_lock);
  
  pthread_mutex_unlock (&flows_lock);
}




// Trim strings 
char *trim(char *str)
{
    size_t len = 0;
    char *frontp = str;
    char *endp = NULL;

    if( str == NULL ) { return NULL; }
    if( str[0] == '\0' ) { return str; }

    len = strlen(str);
    endp = str + len;

    while( isspace((unsigned char) *frontp) ) { ++frontp; }
    if( endp != frontp )
    {   
        while( isspace((unsigned char) *(--endp)) && endp != frontp ) {}
    }   

    if( str + len - 1 != endp )
            *(endp + 1) = '\0';
    else if( frontp != str &&  endp == frontp )
            *str = '\0';

    endp = str;
    if( frontp != str )
    {   
            while( *frontp ) { *endp++ = *frontp++; }
            *endp = '\0';
    }   

    return str;
}
void
parse_config (map <string,double>& parms)
{
  char *s, buff[256];
  FILE *fp = fopen ("as.config", "r");
  if (fp == NULL)
  {
    cout <<"Config file as.config does not exist. Please include it and re-run.. \n";
    exit (0);
  }
  cout << "Reading config file as.config ...";
  while ((
          s = fgets (buff, sizeof buff, fp)) != NULL)
  {
        // Skip blank lines and comment lines 
        if (buff[0] == '\n' || buff[0] == '#')
          continue;

        // Look for = sign and abort if that does not
        // exist
        char name[MAXLINE], value[MAXLINE];
        int found = -1; 
        for(int i=0; i<strlen(buff); i++)
          {   
            if (buff[i] == '=')
              {   
                strncpy(name,buff, i); 
                name[i] = 0;
                found = i;
              }   
            else if((buff[i] == ' ' || buff[i] == '\n') && found >= 0)
              {   
                strncpy(value,buff+found+1,i-found-1);
                value[i-found-1] = 0;
                break;
              }   
          }   
        if (found == -1) 
          continue;
        trim(name);
        trim(value);
        parms.insert(pair<string,double>(name,strtod(value,0)));
  }
  fclose (fp);
}


void readConstraint(unsigned int ts, unsigned int ip, multimap<unsigned int, unsigned int> &constraintMap){

    // multimap <ip, ts> --> one ip : multiple ts
    constraintMap.insert(pair<unsigned int, unsigned int>(ip, ts));


}


unsigned int ipConverter(string ip){

    // convert ip(ip format) to ip(decimal format)
    stringstream ss(ip);
    string c;
    vector<int> r;
    while(getline(ss, c, '.')){
        r.push_back(stoi(c));
    }

    unsigned int decimal = r[0] * 16777216 + r[1] * 65536 + r[2] * 256 + r[3];
    return decimal;

}

int toRange(float f){
  int x=0;
  if (f > 0.0 && f < 10.0){
      x=1;
  }
  else if (f >= 10.0 && f < 100.0){
      x=2;
  }
  else if (f >= 100.0 && f < 1000.0){
      x=3;
  }
  else if (f >= 1000.0 && f < 10000.0){
      x=4;
  }
  else if (f >= 10000.0 && f < 100000.0){
      x=5;
  }
  else if (f >= 100000.0 && f < 500000.0){
      x=6;
  }
  else if (f >= 500000.0 && f < 1000000.0){
      x=7;
  }
  else if (f >= 1000000){
      x=8;
  }
  return x;
}

void readFlow(int protocol, unsigned int ip, int dstPort, float pps, float bps){
  if (protocolCount.count(protocol) == 0){
      protocolCount[protocol] = 0;
  }
  protocolCount[protocol]++;
  unsigned int prefix = ip - (ip % 65536);

  if (dstIPCount.count(prefix) == 0){
    dstIPCount[prefix] = 0;
  }
  dstIPCount[prefix]++;
  if (dstPortCount.count(dstPort) == 0){
      dstPortCount[dstPort] = 0;
  }
  dstPortCount[dstPort]++;
  
  int p = toRange(pps);
  if (ppsCount.count(p) == 0){
    ppsCount[p] = 0;
  }
  ppsCount[p]++;

  int b = toRange(bps);
  if (bpsCount.count(b) == 0){
    bpsCount[b] = 0;
  }
  bpsCount[b]++;
}

// Read nfdump flow format
void
amonProcessingNfdump (char* line)
{
  /* 2|1453485557|768|1453485557|768|6|0|0|0|2379511808|44694|0|0|0|2792759296|995|0|0|0|0|2|0|1|40 */
  char* tokene;
  parse(line,'|', &delimiters);
  long firstSeen = strtol(line+delimiters[0], &tokene, 10);
  long lastSeen = strtol(line+delimiters[2], &tokene, 10);
  int protocol = atoi(line+delimiters[4]);
  unsigned int dstIP = strtol(line+delimiters[13], &tokene, 10);
  int dstPort = atoi(line+delimiters[14]);
  unsigned int packet = atoi(line+delimiters[21]);
  unsigned int flowSize = atoi(line+delimiters[22]);
        int d = lastSeen - firstSeen + 1;
        if (d < 1){
            return;
        }
        float pps = packet/d;       // packets per second
        float bps = flowSize/d;     // bytes per second
        auto mapp = constraintMap.equal_range(dstIP);
            for(auto i = mapp.first; i != mapp.second; i++){
                if (i->second >= firstSeen && i->second <= lastSeen){
                    return;
                }   
            }
     
        readFlow(protocol, dstIP, dstPort, pps, bps);
        ctr++;
}



void readConstraintMap(multimap<unsigned int, unsigned int> &constraintMap){

    // 1519054022 141.214.186.162 pps=11.0 mean=1.41935483871 stdev=1.2270243855 1519054028 FLOOD 80
    /* list of needed columns
    1)  Time first seen UNIX time seconds
    2) Dst address as 4 consecutive 32bit numbers
    6)  Time last seen UNIX time seconds
    */

    ifstream data("constraint.txt");
    string str = "";
    while (getline(data, str)){
        stringstream ss(str);      // string stream
        string col;
        vector<string> row;
        while(getline(ss, col, ' ')){
            row.push_back(col);
        }

        if (row.size() != 8){
            cout << "input error" << endl;
            continue;
        }
        unsigned int firstSeen, lastSeen, dstIP;
        firstSeen = stoul(row[0]);
        lastSeen = stoul(row[5]);
        dstIP = ipConverter(row[1]);

        int d = lastSeen - firstSeen + 1;
        vector<unsigned int> ts;
        if (d <= 0){
            continue;
        }
        else if (d >= 1){
            for (int i = 0; i < d; i ++){
                ts.push_back(firstSeen + i);
            }
        }

        for (int i = 0; i < d; i++){
            unsigned int timestamp = firstSeen + i;
            readConstraint(timestamp, dstIP, constraintMap);
        }

    }
    data.close();
}


// -------------------------------------------------------


void summaryCount(){
  int total_Protocol = 0;
  int total_dstIP = 0;
  int total_dstPort = 0;
  int total_pps = 0;
  int total_bps = 0;
  // compute total
  for (auto i = protocolCount.begin(); i != protocolCount.end(); i++){
    total_Protocol+=i->second;
  }
  for (auto i = dstIPCount.begin(); i != dstIPCount.end(); i++){
    total_dstIP+=i->second;
  }
  for (auto i = dstPortCount.begin(); i != dstPortCount.end(); i++){
    total_dstPort+=i->second;
  }
  for (auto i = ppsCount.begin(); i != ppsCount.end(); i++){
    total_pps+=i->second;
  }
  for (auto i = bpsCount.begin(); i != bpsCount.end(); i++){
    total_bps+=i->second;
  }
  // update count to ratio
  for (auto i = protocolCount.begin(); i != protocolCount.end(); i++){
    protocolCount[i->first] = i->second/total_Protocol;
  }
  for (auto i = dstIPCount.begin(); i != dstIPCount.end(); i++){
    dstIPCount[i->first] = i->second/total_dstIP;
  }
  for (auto i = dstPortCount.begin(); i != dstPortCount.end(); i++){
    dstPortCount[i->first] = i->second/total_dstPort;
  }
  for (auto i = ppsCount.begin(); i != ppsCount.end(); i++){
    ppsCount[i->first] = i->second/total_pps;
  }
  for (auto i = bpsCount.begin(); i != bpsCount.end(); i++){
    bpsCount[i->first] = i->second/total_bps;
  }
}

void updateProfile(){
  for (auto i = protocolCount.begin(); i != protocolCount.end(); i++){
    if (protocolMap.count(i->first) == 0){
      protocolMap[i->first] = i->second;
    }
    else{
        protocolMap[i->first] = max(protocolMap[i->first], i->second);
    }
  }
  for (auto i = dstIPCount.begin(); i != dstIPCount.end(); i++){
    if (dstIPMap.count(i->first) == 0){
      dstIPMap[i->first] = i->second;
    }
    else{
      dstIPMap[i->first] = max(dstIPMap[i->first], i->second);
    }
  }
  for (auto i = dstPortCount.begin(); i != dstPortCount.end(); i++){
    if (dstPortMap.count(i->first) == 0){
      dstPortMap[i->first] = i->second;
    }
    else{
      dstPortMap[i->first] = max(dstPortMap[i->first], i->second);
    }
  }
  for (auto i = ppsCount.begin(); i != ppsCount.end(); i++){
    if (ppsMap.count(i->first) == 0){
      ppsMap[i->first] = i->second;
    }
    else{
      ppsMap[i->first] = max(ppsMap[i->first], i->second);
    }
  }
  for (auto i = bpsCount.begin(); i != bpsCount.end(); i++){
    if (bpsMap.count(i->first) == 0){
      bpsMap[i->first] = i->second;
    }
    else{
      bpsMap[i->first] = max(bpsMap[i->first], i->second);
    }
  }
}

void clearCount(){
  map<int, float>().swap(protocolCount);
  map<unsigned int, float>().swap(dstIPCount);
  map<int, float>().swap(dstPortCount);
  map<int, float>().swap(ppsCount);
  map<int, float>().swap(bpsCount);
}

void printProfile(){
  cout << "protocol nominal profile" << endl;
  for (auto i = protocolMap.begin(); i != protocolMap.end(); i++){
    cout << i->first << " " << i->second << endl;
  }
  cout << "destination IP nominal profile" << endl;
  for (auto i = dstIPMap.begin(); i != dstIPMap.end(); i++){
    cout << i->first << " " << i->second << endl;
  }
  cout << "destination Port nominal profile" << endl;
  for (auto i = dstPortMap.begin(); i != dstPortMap.end(); i++){
    cout << i->first << " " << i->second << endl;
  }
  cout << "packets per second nominal profile" << endl;
  for (auto i = ppsMap.begin(); i != ppsMap.end(); i++){
    cout << i->first << " " << i->second << endl;
  }
  cout << "bytes per second nominal profile" << endl;
  for (auto i = bpsMap.begin(); i != bpsMap.end(); i++){
    cout << i->first << " " << i->second << endl;
  }
}

// Ever so often go through flows and process what is ready
void *reset_transmit (void* passed_parms)
{
/*  while (1)
    {
      // Serialize access to flows
      pthread_mutex_lock (&flows_lock);
      
      // Release access to flows
      pthread_mutex_unlock (&flows_lock);
      pthread_mutex_unlock (&cells_lock);
      // Sleep a bit and try again
      sleep(1);
    }
  pthread_exit (NULL);
*/
}

bool compareNat(const std::string& a, const std::string& b)
{   
    if (a.empty())
        return true;
    if (b.empty())
        return false;
    if (std::isdigit(a[0]) && !std::isdigit(b[0]))
        return true;
    if (!std::isdigit(a[0]) && std::isdigit(b[0]))
        return false;
    if (!std::isdigit(a[0]) && !std::isdigit(b[0]))
    {   
        if (std::toupper(a[0]) == std::toupper(b[0]))
            return compareNat(a.substr(1), b.substr(1));
        return (std::toupper(a[0]) < std::toupper(b[0]));
    }
        std::istringstream issa(a);
        std::istringstream issb(b);
        int ia, ib;
        issa >> ia;
        issb >> ib;
        if (ia != ib)
            return ia < ib;

       std::string anew, bnew;
       std::getline(issa, anew);
       std::getline(issb, bnew);
       return (compareNat(anew, bnew));
}



// Print help for the program
void
printHelp (void)
{
  printf ("-h                             Print this help\n");
  printf ("-r <inputfile or inputfolder>  Input is in nfdump or flow-tools file(s)\n");
  printf ("-l                             Load historical data from as.dump\n");
  printf ("-v                             Verbose\n");
}


// Main program
int main (int argc, char *argv[])
{
  delimiters = (int*)malloc(AR_LEN*sizeof(int));
  // Parse configuration
  parse_config (parms);
  // Load service port numbers
  
  char c, buf[32];
  char *file_in = NULL;

  
  while ((c = getopt (argc, argv, "hvlr:")) != '?')
    {
      if ((c == 255) || (c == -1))
	break;

      switch (c)
	{
	case 'h':
	  printHelp ();
	  return (0);
	  break;
	case 'r':
	  file_in = strdup (optarg);
	  break;
	case 'v':
	  verbose = 1;
	  break;
	}
    }
  if (file_in == NULL)
    {
      cerr<<"You must specify an input folder, which holds Netflow records\n";
      exit(-1);
    }
  //cout<<"Verbose "<<verbose<<endl;
  // Prepare debug files

  srand (seed);
  init_tables16 (T1_16, T2_16, T3_17);
  readConstraintMap(constraintMap);

  int reserved = 0;
  int STRATA_index = 0;
  u_int32_t IP_prefix = 0;
  char line[80];
  init_STRATA_IDX17 (STRATA_IDX17_prefix_bin);

  FILE *fid;
  fid = fopen ("strata.txt", "rt");
  if (fid != NULL)
    { 
      while (fgets (line, 80, fid) != NULL)
        { 
          sscanf (line, "%u %d", &IP_prefix, &STRATA_index);
          if (STRATA_index > reserved)
            { 
              reserved = STRATA_index;
            }
          update_STRATA_IDX17 (STRATA_IDX17_prefix_bin,
                               (u_int32_t) IP_prefix >> 15, STRATA_index);
        }
      fclose (fid);
    }
  reserved += 1;                // +1 because we have C-based indexing starting from 0
  init_IDX17 (IDX17, reserved);
 



  pthread_t thread_id;
  pthread_create (&thread_id, NULL, reset_transmit, NULL);

  // This is going to be a pointer to input
  // stream, either from nfdump or flow-tools */
  FILE* nf;
  unsigned long long num_pkts = 0;      

  // Read flows from a file
  if (file_in)
    {
      int isdir = 0;
      vector<string> tracefiles;
      vector<string> inputs;
      struct stat s;
      inputs.push_back(file_in);
      int i = 0;
      // Recursively read if there are several directories that hold the files
      while(i < inputs.size())
	{
	  if( stat(inputs[i].c_str(),&s) == 0 )
	    {
	      if(s.st_mode & S_IFDIR )
		{
		  // it's a directory, read it and fill in 
		  // list of files
		  DIR *dir;
		  struct dirent *ent;

		  if ((dir = opendir (inputs[i].c_str())) != NULL) {
		    // Remember all the files and directories within directory 
		    while ((ent = readdir (dir)) != NULL) {
		      if((strcmp(ent->d_name,".") != 0) && (strcmp(ent->d_name,"..") != 0)){
			inputs.push_back(string(inputs[i]) + "/" + string(ent->d_name));
		      }
		    }
		    closedir (dir);
		  } else {
		    perror("Could not read directory ");
		    exit(1);
		  }
		}
	      else if(s.st_mode & S_IFREG)
		{
		  tracefiles.push_back(inputs[i]);
		}
	      // Ignore other file types
	    }
	  i++;
	}
      
      //std::sort(tracefiles.begin(), tracefiles.end(), sortbyFilename());
      std::sort(tracefiles.begin(), tracefiles.end(), compareNat);
      // Go through tracefiles and read each one
      for (vector<string>::iterator vit=tracefiles.begin(); vit != tracefiles.end(); vit++)
      {
	const char* file = vit->c_str();
	
	char cmd[MAXLINE];
	// Try to read as netflow file
	sprintf(cmd,"/home/MERIT/rajattan/nfdump/nfdump/bin/nfdump -r %s -o pipe 2>/dev/null", file);
	nf = popen(cmd, "r");
	// Close immediately so we get the error code 
	// and we can detect if this is maybe flow-tools format 
	int error = pclose(nf);
	if (error == 64000)
	  {
	    sprintf(cmd,"/home/MERIT/rajattan/nfdump/nfdump/bin/ft2nfdump -r %s | /home/MERIT/rajattan/nfdump/nfdump/bin/nfdump -r - -o pipe", file);
	    nf = popen(cmd, "r");
	  }
	else
	  {
	    nf = popen(cmd, "r");
	  }
	if (!nf)
	  {
	    fprintf(stderr,"Cannot open file %s for reading. Unknown format.\n", file);
	    exit(1);
	  }
        
	char line[MAXLINE];
	cout<<"Reading from "<<file<<" time "<<time(0)<<endl;
	while (fgets(line, MAXLINE, nf) != NULL)
	  {
	    // Check that this is the line with a flow
	    char tmpline[255];
	    strcpy(tmpline, line);
	    if (strstr(tmpline, "|") == NULL)
	      continue;
            //auto t1 = std::chrono::high_resolution_clock::now();
    
	    amonProcessingNfdump(line);
        if (ctr == 10000){
            summaryCount();
            updateProfile();
            clearCount();
            ctr = 0;
        }
            //auto t2 = std::chrono::high_resolution_clock::now();
            //  auto duration = std::chrono::duration_cast<std::chrono::microseconds>( t2 - t1 ).count();

            //std::cout << duration<<endl;

	  }

	cout<<"Done with the file "<<file<<" time "<<time(0)<<endl;
	pclose(nf);
      }
      printProfile();
      //print_res();
    }
  return 0;
}
