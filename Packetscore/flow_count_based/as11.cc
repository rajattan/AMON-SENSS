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
#include <vector>
#include <string>
#include <queue>
#include <dirent.h>
#include "utils.h"
#include "haship.h"
#include "haship.c"
#include <chrono>

using namespace std;
double q_prev=0.0;
double q_current=0.0;
double phi = 0.0;
double qmin=500000000;
double qmax=10000000000;
float omega=0.05;
float fnplusone=1.0;
float fminval= 0.005;
long long tot_flows=0;
map<int, float> protocolProfile;            // <protocol, profile>
map<unsigned int, float> dstIPProfile;      // <dst ip (prefix), profile>
map<int, float> dstPortProfile;             // <dst port, profile>
map<int, float> packetProfile;              // <pps, profile>
map<int, float> flowProfile;                // <bps, profile>

//typedef pair<float, string> flow;
map<int, float> protocolMeasured;
map<unsigned int, float> dstIPMeasured;
map<int, float> dstPortMeasured;
map<int, float> ppsMeasured;
map<int, float> bpsMeasured;
float FLOWCOUNT = 10000.0;
float total_Protocol = FLOWCOUNT;
float total_dstIP = FLOWCOUNT;
float total_dstPort = FLOWCOUNT;
float total_pps = FLOWCOUNT;
float total_bps = FLOWCOUNT;
float divi = (1.0/10000.0);



int ctr = 0;
long long  totalBytes = 0;
map<int, string> interval;
priority_queue<pair<float, string>> flowScore;
map<string, float> scoreFlow;
map<float, string> flowCDF;

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
//pthread_mutex_t cells_lock = PTHREAD_MUTEX_INITIALIZER;
//pthread_mutex_t flows_lock = PTHREAD_MUTEX_INITIALIZER;

// Parameters from as.config
map<string,double> parms;
int SIZE = 28910;
/*
void amonProcessing(flow_t flow, int len, long start, long end, int oci)
{
  pthread_mutex_lock (&flows_lock);
  
  pthread_mutex_unlock (&flows_lock);
}
*/

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

void readProfile(){

    ifstream data("nominal_profile.txt");
    string str = "";
    string prf = "";
    while (getline(data, str)){
        stringstream ss(str);      // string stream
        string col;
        vector<string> row;
        while(getline(ss, col, ' ')){
            row.push_back(col);
        }
        if (row[0] == "protocol"){
            prf = "protocol";
            continue;
        }
        if (row[0] == "destination" && row[1] == "IP"){
            prf = "dstIP";
            continue;
        }
        if (row[0] == "destination" && row[1] == "Port"){
            prf = "dstPort";
            continue;
        }
        if (row[0] == "packets"){
            prf = "pps";
            continue;
        }
        if (row[0] == "bytes"){
            prf = "bps";
            continue;
        }

        if (prf == "protocol"){
            protocolProfile[std::stoi(row[0])] = std::stof(row[1]);
        }
        else if (prf == "dstIP"){
            dstIPProfile[std::stoul(row[0])] = std::stof(row[1]);
        }
        else if (prf == "dstPort"){
            dstPortProfile[std::stoi(row[0])] = std::stof(row[1]);
        }
        else if (prf == "pps"){
            packetProfile[std::stoi(row[0])] = std::stof(row[1]);
        }
        else if (prf == "bps"){
            flowProfile[std::stoi(row[0])] = std::stof(row[1]);
        }
    }
    data.close();
    cout<<endl<<"HERE    \n";

  map<int, float>::iterator j; 
  for(j = flowProfile.begin(); j != flowProfile.end(); j++){
            cout << "F " << j->first << " " << j->second << endl;
        }

  for(j = protocolProfile.begin(); j != protocolProfile.end(); j++){
            cout << "P " << j->first << " " << j->second << endl;
        }

  for(j = dstPortProfile.begin(); j != dstPortProfile.end(); j++){
            cout << "D " << j->first << " " << j->second << endl;
        }
   map<unsigned int, float>::iterator i;
  for(i = dstIPProfile.begin(); i != dstIPProfile.end(); i++){
            cout << "T " << i->first << " " << i->second << endl;
        }


}

void readFlow(int protocol, unsigned int ip, int dstPort, float pps, float bps){
    if (protocolMeasured.count(protocol) == 0){
        protocolMeasured[protocol] = 0;
    }
    protocolMeasured[protocol]++;

    unsigned int prefix = ip - (ip % 65536);
    if (dstIPMeasured.count(prefix) == 0){
        dstIPMeasured[prefix] = 0;
    }
    dstIPMeasured[prefix]++;

    if (dstPortMeasured.count(dstPort) == 0){
        dstPortMeasured[dstPort] = 0;
    }
    dstPortMeasured[dstPort]++;
    
    int p = toRange(pps);
    if (ppsMeasured.count(p) == 0){
        ppsMeasured[p] = 0;
    }
    ppsMeasured[p]++;

    int b = toRange(bps);
    if (bpsMeasured.count(b) == 0){
        bpsMeasured[b] = 0;
    }
    bpsMeasured[b]++;
}

// Read nfdump flow format
void
amonProcessingNfdump (char* line)
{
    /* 2|1453485557|768|1453485557|768|6|0|0|0|2379511808|44694|0|0|0|2792759296|995|0|0|0|0|2|0|1|40 */
    char* tokene;
    int* delimiters;
    delimiters = (int*)malloc(AR_LEN*sizeof(int));
    parse(line,'|', &delimiters);
    long firstSeen = strtol(line+delimiters[0], &tokene, 10);
    long lastSeen = strtol(line+delimiters[2], &tokene, 10);
    int protocol = atoi(line+delimiters[4]);
    unsigned int srcIP = strtol(line+delimiters[8], &tokene, 10);
    int srcPort = atoi(line+delimiters[9]);
    unsigned int dstIP = strtol(line+delimiters[13], &tokene, 10);
    int dstPort = atoi(line+delimiters[14]);
    unsigned int packet = atoi(line+delimiters[21]);
    unsigned int flowSize = atoi(line+delimiters[22]);
    //cout<<endl<<firstSeen<<lastSeen<<protocol<<srcIP<<srcPort<<dstIP<<dstPort<<packet<<flowSize<<endl;
    //cout<<endl;

    string v = "";
    v.append(to_string(firstSeen));
    v.append(" ");
    v.append(to_string(lastSeen));
    v.append(" ");
    v.append(to_string(protocol));
    v.append(" ");
    v.append(to_string(srcIP));
    v.append(" ");
    v.append(to_string(srcPort));
    v.append(" ");
    v.append(to_string(dstIP));
    v.append(" ");
    v.append(to_string(dstPort));
    v.append(" ");
    v.append(to_string(packet));
    v.append(" ");
    v.append(to_string(flowSize));

    int d = lastSeen - firstSeen + 1;
    if (d < 1){
        return;
    }
    float pps = packet/d;       // packets per second
    float bps = flowSize/d;     // bytes per second

    readFlow(protocol, dstIP, dstPort, pps, bps);
    ctr++;
    totalBytes+=flowSize;
    interval[ctr] = v;
    free(delimiters);
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


void updateQ()
{

        if (q_prev == 0){
            q_prev = totalBytes;
        }

    q_current = (1.0-omega)*q_prev + omega*totalBytes;

        if(q_current >= qmax)
        {
            fnplusone = fminval;
        }
        else if(q_current <= qmin)
        {
            fnplusone = 1;
        }
        else
        {
            float v = (qmax - q_current)/(qmax - qmin);
            if(v >= fminval)
            {
            fnplusone = v; 
            }
            else
            {
            fnplusone = fminval;
            }
        }
        phi = 1-fnplusone;
        q_prev = q_current;       
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

string decimalToIP(unsigned int dIP){
    string ip = "";
    for (int i = 4; i > 0; i--){
        string temp = "";
        if (i == 4){
            int t = (int)(dIP/16777216);
            temp = to_string(t);
            ip = ip + temp + ".";
            dIP = dIP - (t * 16777216);
        }
        if (i == 3){
            int t = (int)(dIP/65536);
            temp = to_string(t);
            ip = ip + temp + ".";
            dIP = dIP - (t * 65536);
        }
        if (i == 2){
            int t = (int)(dIP/256);
            temp = to_string(t);
            ip = ip + temp + ".";
            dIP = dIP - (t * 256);
        }
        if (i == 1){
            temp = to_string((int)dIP);
            ip = ip + temp;
        }
    }
    return ip;
}

void summaryMeasured(){
/*    int total_Protocol = 0;
    int total_dstIP = 0;
    int total_dstPort = 0;
    int total_pps = 0;
    int total_bps = 0;
    // compute total
    for (auto i = protocolMeasured.begin(); i != protocolMeasured.end(); i++){
        total_Protocol+=i->second;
    }
    for (auto i = dstIPMeasured.begin(); i != dstIPMeasured.end(); i++){
        total_dstIP+=i->second;
    }
    for (auto i = dstPortMeasured.begin(); i != dstPortMeasured.end(); i++){
        total_dstPort+=i->second;
    }
    for (auto i = ppsMeasured.begin(); i != ppsMeasured.end(); i++){
        total_pps+=i->second;
    }
    for (auto i = bpsMeasured.begin(); i != bpsMeasured.end(); i++){
        total_bps+=i->second;
    }
*/
    // update measured to ratio
    for (auto i = protocolMeasured.begin(); i != protocolMeasured.end(); i++){
        protocolMeasured[i->first] = i->second/total_Protocol;
    }
    for (auto i = dstIPMeasured.begin(); i != dstIPMeasured.end(); i++){
        dstIPMeasured[i->first] = i->second/total_dstIP;
    }
    for (auto i = dstPortMeasured.begin(); i != dstPortMeasured.end(); i++){
        dstPortMeasured[i->first] = i->second/total_dstPort;
    }
    for (auto i = ppsMeasured.begin(); i != ppsMeasured.end(); i++){
        ppsMeasured[i->first] = i->second/total_pps;
    }
    for (auto i = bpsMeasured.begin(); i != bpsMeasured.end(); i++){
        bpsMeasured[i->first] = i->second/total_bps;
    }
}

void scoreProcessing(){
    // iterate and score each flow (1 interval)
    // store each score to the priority queue of flow score (max heap)
    for (auto i = interval.begin(); i != interval.end(); i++){
        stringstream ss(i->second);
        vector<string> fl;
        string attr;    // attribute
        while (ss >> attr){
            fl.push_back(attr);
        }
        // {fs(0), ls(1), protocol(2), srcIP(3), srcPort(4), dstIP(5), dstPort(6), packets(7), bytes(8)}
        // score = protocol + dstIP + dstPort + pps + bps (log version)
        unsigned int fs = stoul(fl[0]);
        unsigned int ls = stoul(fl[1]);
        int protocol = stoi(fl[2]);
        unsigned int dstIP = stoul(fl[5]);
        dstIP = dstIP - (dstIP % 65536);
        //cout<<endl<<"IP:"<<dstIP<<endl;
        int dstPort = stoi(fl[6]);
        unsigned int packets = stoul(fl[7]);
        unsigned int bytes = stoul(fl[8]);

        int d = ls - fs + 1;

        int pps = toRange(packets/d);
        int bps = toRange(bytes/d);
        float protocolScore =  - log((protocolMeasured[protocol]/total_Protocol)+1.0);
        float dstIPScore = - log((dstIPMeasured[dstIP]/total_dstIP)+1.0);
        float dstPortScore = - log((dstPortMeasured[dstPort]/total_dstPort)+1.0);
        float ppsScore = - log((ppsMeasured[pps]/total_pps)+1.0);
        float bpsScore = - log((bpsMeasured[bps]/total_bps)+1.0);
        //cout<<endl<<dstIPMeasured[dstIP]<<" " <<dstIP;
        
        if(protocolProfile.count(protocol) != 0)
        {
           protocolScore += log(protocolProfile[protocol]+1.0);
        }
        if(dstIPProfile.count(dstIP) != 0)
        {
           dstIPScore += log(dstIPProfile[dstIP]+1.0);
        }

        if(dstPortProfile.count(dstPort) !=0)
        {
           dstPortScore += log(dstPortProfile[dstPort]+1.0);
        }
        if(packetProfile.count(pps) !=0)
        {
        ppsScore += log(packetProfile[pps]+1.0);
        }
        if(flowProfile.count(bps) != 0)
        {
        bpsScore += log(flowProfile[bps]+1.0);
        }
       //cout<<endl<<protocolScore<<" "<<dstIPScore<<" "<<dstPortScore<<" "<<ppsScore<<" "<<bpsScore<<"  All"<<endl;

        float score = protocolScore + dstIPScore + dstPortScore + ppsScore + bpsScore;

        // push (score, flow detail(i->second)) in the flowScore priority queue (max heap)
        //cout<<endl<<score<<" Score "<<endl;
        flowScore.push(make_pair(score, i->second));
    }
}

void cdfProcessing(){
    float cdf = 1.0;
    while (!flowScore.empty()){
        float score = flowScore.top().first;
        string flow = flowScore.top().second;
        flowCDF[cdf] = flow;
        //cout<<endl<<cdf<<" :abc: "<<flowCDF[cdf]<<" "<<score<<endl;
        scoreFlow[flow] = score;
        cdf-=divi;
        flowScore.pop();
    }
}

void printAlert(){
    if (phi == 0.0){
        //cout << "nothing to discard" << endl;
        return;
    }
    for (auto i = flowCDF.begin(); i != flowCDF.end(); i++){    // default map order in ascending order
        float cdf = i->first;
        string f = i->second;
        if (cdf < phi){
            cout << "phi = " << phi <<endl;
            cout << " Qcurrent = "<<q_current<<" Total Bytes = "<<totalBytes<<endl;
            cout << "Discarded flows" << endl;
            //while (cdf <= 1){
            while(cdf < phi){
                // string processing
                string str = flowCDF[cdf];
                stringstream ss(str);
                vector<string> flow;
                string attr; // attribute
                while (ss >> attr){
                    flow.push_back(attr);
                }
                // print flow detail
                // fs(0) | ls(1) | protocol(2) | srcIP(3) | srcPort(4) | dstIP(5) | dstPort(6) | packets(7) | bytes(8)
                for (int j = 0; j <= 8; j++){
                    if(j==0)
                    {
			cout<<endl;
                    }
                    if (j == 3 || j == 5){
			    unsigned int ip = stoul(flow[j]);
                            char* ip_ad;
			    sprintf(ip_ad, "%d.%d.%d.%d",(ip >> 24) & 0xFF,(ip >> 16) & 0xFF,(ip >>  8) & 0xFF,(ip      ) & 0xFF);

                        //string ip = decimalToIP(stoul(flow[j]));
                        cout << ip_ad <<" ";
                    }
                    else if (j == 8){
                        cout << flow[j];
                        cout << " score = " << scoreFlow[str];
                        cout << " cdf = " << cdf ;
                    }
                    else {
                        cout << flow[j] << " ";
                    }
                }
                cdf+=divi;
            }
            break;
        }
    }
}
/*
void printAlert(){
    if (phi == 1.0){
        cout << "nothing to discard" << endl;
        return;
    }
    float i;
    if (flowCDF.count(phi) == 0){
        float temp = phi * 10000;
        temp = ceil(temp);
        i = temp/10000;
    }
    else {
        i = phi + 1/10000;
    }
    cout << "phi = " << phi << endl;
    cout << "Discarded flows" << endl;
    while (i <= 1){
        // string processing
        cout << endl << i<<"="<<endl;
        string str = flowCDF[i];
        cout << endl <<str<<"HERE="<<endl;
        stringstream ss(str);
        vector<string> flow;
        string attr; // attribute
        while (ss >> attr){
            flow.push_back(attr);
        }
        // print flow detail
        // fs(0) | ls(1) | protocol(2) | srcIP(3) | srcPort(4) | dstIP(5) | dstPort(6) | packets(7) | bytes(8)
        for (int j = 0; j <= 8; j++){
            if (j == 3 || j == 5){
                string ip = decimalToIP(stoul(flow[j]));
                cout << ip << " ";
            }
            else if (j == 8){
                cout << flow[j] << endl;
                cout << "score = " << scoreFlow[str] << endl;
                cout << "cdf = " << i << endl;
            }
            else {
                cout << flow[i] << " ";
            }
        }
        i+=1/10000;
    }
}
*/
void clearMemory(){
    map<int, float>().swap(protocolMeasured);
    map<unsigned int, float>().swap(dstIPMeasured);
    map<int, float>().swap(dstPortMeasured);
    map<int, float>().swap(ppsMeasured);
    map<int, float>().swap(bpsMeasured);

    map<int, string>().swap(interval);
    priority_queue<pair<float, string>>().swap(flowScore);
    map<string, float>().swap(scoreFlow);
    map<float, string>().swap(flowCDF);
}

// Ever so often go through flows and process what is ready
void *reset_transmit (void* passed_parms)
{
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
  parse_config (parms);
  
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
  cout<<endl<<"Reading trained profile \n";
  readProfile();
  cout<<endl<<"Done reading trained profile \n";

  int reserved = 0;
  int STRATA_index = 0;
  char line[80];
  // We dont need ========= 
  FILE *fid;
 
  //pthread_t thread_id;
 // pthread_create (&thread_id, NULL, reset_transmit, NULL);

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
        for (vector<string>::iterator vit=tracefiles.begin(); vit != tracefiles.end();vit++)
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
                if (ctr == 10000){          // 1 interval = 10000 flows
                    //summaryMeasured();
                    scoreProcessing();
                    cdfProcessing();
                    updateQ();
                    printAlert();
                    clearMemory();
                    tot_flows = tot_flows + ctr;
                    ctr = 0;
                    totalBytes = 0;
                }
            }
            cout<<"Done with the file "<<file<<" time "<<time(0)<<endl;
            cout<<"Total Flows = "<<tot_flows;
            pclose(nf);
        }
    }
    return 0;
}
