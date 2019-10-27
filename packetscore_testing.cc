
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

map<unsigned int, map<float, float> > flowMap;             // <timestamp, bytes per sec, amount>
map<unsigned int, map<int, float> > protocolMap;           // <timestamp, protocol, amount>
map<unsigned int, map<unsigned int, float> > dstIPMap;     // <timestamp, dst ip(prefix /24), amount>
map<unsigned int, map<int, float> > dstPortMap;            // <timestamp, dst port, amount>
multimap<unsigned int, unsigned int> constraintMap;
map<unsigned int, double> traffic_at_Ti;
map<unsigned int, double> q_map;
double qmin=56000000000;
double qmax=101000000000;
float omega=0.05;
float fnplusone=1.0;
float fmin=1.0;

map<int, float> flowProfile;                // <range of bypes, profile>
map<int, float> protocolProfile;            // <protocol, profile>
map<unsigned int, float> dstIPProfile;      // <dst ip (prefix), profile>
map<int, float> dstPortProfile;             // <dst port, profile>
map<unsigned int, float> phi;




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


void readProtocol(unsigned int ts, int protocol, int d){

    // protocolMap hasn't had this ts(key) yet
   /* if (protocolMap.count(ts) == 0){
        protocolMap[ts];
    }*/
    // protocolMap[ts] hasn't had this protocol(key) yet
    for(int i=0; i<d;i++)
    {
    if (protocolMap[ts].count(protocol) == 0){
        protocolMap[ts][protocol] = 0;
    }
    protocolMap[ts][protocol]++;
    ts=ts+30;
    }

}


void readProfile(){

    ifstream data("packetscore_data.txt");
    string str = "";
    while (getline(data, str)){
        stringstream ss(str);      // string stream
        string col;
        vector<string> row;
        while(getline(ss, col, ' ')){
            row.push_back(col);
        }

        if (row.size() != 3){
            /*cout << "input error" << Lendl;
            cout << row[0] << endl;*/
            continue;
        }

        if (row[0] == "R"){
            int rob = stoul(row[1]);    // rob = range of bytes
            if (flowProfile.count(rob) == 0){
                flowProfile[rob] = stof(row[2]);
            }
            else{
                if (stof(row[2]) > flowProfile[rob]){
                    flowProfile[rob] = stof(row[2]);
                }
            }
        }
        else if (row[0] == "P"){
            int protocol = stoul(row[1]);
            if (protocolProfile.count(protocol) == 0){
                protocolProfile[protocol] = stof(row[2]);
            }
            else{
                if (stof(row[2]) > protocolProfile[protocol]){
                    protocolProfile[protocol] = stof(row[2]);
                }
            }
        }
        else if (row[0] == "I"){
            unsigned int dstIP = stoul(row[1]);
            if (dstIPProfile.count(dstIP) == 0){
                dstIPProfile[dstIP] = stof(row[2]);
            }
            else {
                if (stof(row[2]) > dstIPProfile[dstIP]){
                    dstIPProfile[dstIP] = stof(row[2]);
                }
            }
        }
        else if (row[0] == "T"){
            int dstPort = stoul(row[1]);
            if (dstPortProfile.count(dstPort) == 0){
                dstPortProfile[dstPort] = stof(row[2]);
            }
            else{
                if (stof(row[2]) > dstPortProfile[dstPort]){
                    dstPortProfile[dstPort] = stof(row[2]);
                }
            }
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

void readSize(unsigned int ts, float bps, int d){
 
    int x=0;
    if (bps > 0.0 && bps < 10.0){
        x=1;
    }
    else if (bps >= 10.0 && bps < 100.0){
        x=2;
    }
    else if (bps >= 100.0 && bps < 1000.0){
        x=3;
    }
    else if (bps >= 1000.0 && bps < 10000.0){
        x=4;
    }
    else if (bps >= 10000.0 && bps < 100000.0){
        x=5;
    }
    else if (bps >= 100000.0 && bps < 500000.0){
        x=6;
    }
    else if (bps >= 500000.0 && bps < 1000000.0){
        x=7;
    }
    else if (bps >= 1000000){
        x=8;
    }

    for(int i=0; i<d;i++)
    {
    if (flowMap.count(ts) == 0){
        flowMap[ts][1] = 0;                   // range 1)     1 - 9 (1 digit)
        flowMap[ts][2] = 0;                   // range 2)     10 - 99 (2 digits)
        flowMap[ts][3] = 0;                   // range 3)     100 - 999 (3 digits)
        flowMap[ts][4] = 0;                   // range 4)     1000 - 9999 (4 digits)
        flowMap[ts][5] = 0;                   // range 5)     10000 - 99999 (5 digits)
        flowMap[ts][6] = 0;                   // range 6.1)   100000 - 499999 (6 digits)
        flowMap[ts][7] = 0;                   // range 6.2)   500000 - 999999 (6 digits)
        flowMap[ts][8] = 0;                   // range 7)     > 1000000 (more than 7 digits)
    }
    if(traffic_at_Ti.count(ts) == 0)
    {
        traffic_at_Ti[ts] = 0;
    }

        traffic_at_Ti[ts] = traffic_at_Ti[ts]+bps;

        flowMap[ts][x]++;
        ts=ts+30;
    }
}

void updateQ()
{

  map<unsigned int, float>::iterator j; 
  for(j = traffic_at_Ti.begin(); j != traffic_at_Ti.end(); j++){
           unsigned int key = j->first;
           unsigned int key_plus = key + 30;
           if (q_map.count(key) == 0){
               q_map[key] = j->second;
           }

 	    q_map[key_plus] = (1.0-omega)*q_map[key] + omega*j->second;

            if(q_map[key] >= qmax)
            {
              fnplusone = fmin;
            }
            else if(q_map[key] <= qmin)
            {
              fnplusone = 1;
            }
            else
            {
              float v = (qmax - q_map[key])/(qmax - qmin);
              if(v >= fmin)
              {
                fnplusone = v; 
              }
              else
              {
                fnplusone = fmin;
              }
            }
            if(fnplusone < fmin)
            {
               fmin = fnplusone;

 	    }
           phi[key_plus] = fnplusone;
        }
}

void dstPortCLP(map<unsigned int, map<int, float> > &dstPortMap){

    map<unsigned int, unsigned int> dstPortTotal;  // <ts, total>
    map<unsigned int, map<int, float> >::iterator i;
    map<int, float>::iterator j;
    for(i = dstPortMap.begin(); i != dstPortMap.end(); i++){
        if (dstPortTotal.count(i->first) == 0){
            dstPortTotal[i->first] = 0;
        }
        for(j = i->second.begin(); j != i->second.end(); j++){
            dstPortTotal[i->first] = dstPortTotal[i->first] + j->second;
        }
        // CLP calculation
        for(j = i->second.begin(); j != i->second.end(); j++){
            float pm = j->second/dstPortTotal[i->first];   // Pm
            dstPortMap[i->first][j->first] = log10(dstPortProfile[j->first]) - log10(pm);     // log version CLP (Pn/Pm)
        }
    }

    /* print protocolTotal
    for (auto i = protocolTotal.begin(); i != protocolTotal.end(); i++){
        cout << i->first << " : " << i->second << endl;
    }
    */

}


void dstIPCLP(map<unsigned int, map<unsigned int, float> > &dstIPMap){

    map<unsigned int, unsigned int> dstIPTotal;  // <ts, total>
    map<unsigned int, map<unsigned int, float> >::iterator i;
    map<unsigned int, float>::iterator j;
    for(i = dstIPMap.begin(); i != dstIPMap.end(); i++){
        if (dstIPTotal.count(i->first) == 0){
            dstIPTotal[i->first] = 0;
        }
        for(j = i->second.begin(); j != i->second.end(); j++){
            dstIPTotal[i->first] = dstIPTotal[i->first] + j->second;
        }
        // CLP calculation
        for(j = i->second.begin(); j != i->second.end(); j++){
            float pm = j->second/dstIPTotal[i->first];   // Pm
            dstIPMap[i->first][j->first] = log10(dstIPProfile[j->first]) - log10(pm);     // log version CLP (Pn/Pm)
        }
    }

    /* print protocolTotal
    for (auto i = protocolTotal.begin(); i != protocolTotal.end(); i++){
        cout << i->first << " : " << i->second << endl;
    }
    */

}

void protocolCLP(map<unsigned int, map<int, float> > &protocolMap){

    map<unsigned int, unsigned int> protocolTotal;  // <ts, total>
    map<unsigned int, map<int, float> >::iterator i;
    map<int, float>::iterator j;
    for(i = protocolMap.begin(); i != protocolMap.end(); i++){
        if (protocolTotal.count(i->first) == 0){
            protocolTotal[i->first] = 0;
        }
        for(j = i->second.begin(); j != i->second.end(); j++){
            protocolTotal[i->first] = protocolTotal[i->first] + j->second;
        }
        // CLP calculation
        for(j = i->second.begin(); j != i->second.end(); j++){
            float pm = j->second/protocolTotal[i->first];   // Pm
            protocolMap[i->first][j->first] = log10(protocolProfile[j->first]) - log10(pm);     // log version CLP (Pn/Pm)
        }
    }

    /* print protocolTotal
    for (auto i = protocolTotal.begin(); i != protocolTotal.end(); i++){
        cout << i->first << " : " << i->second << endl;
    }
    */

}


void flowCLP(map<unsigned int, map<int, float> > &flowMap){
    map<unsigned int, unsigned int> flowTotal;  // <ts, total>
    map<unsigned int, map<int, float> >::iterator i;
    map<int, float>::iterator j;
    for(i = flowMap.begin(); i != flowMap.end(); i++){
        if (flowTotal.count(i->first) == 0){
            flowTotal[i->first] = 0;
        }
        for(j = i->second.begin(); j != i->second.end(); j++){
            flowTotal[i->first] = flowTotal[i->first] + j->second;
        }
        // CLP calculation
        for(j = i->second.begin(); j != i->second.end(); j++){
            float pm = j->second/flowTotal[i->first];   // Pm
            flowMap[i->first][j->first] = log10(flowProfile[j->first]) - log10(pm);     // log version CLP (Pn/Pm)
        }
    }

    /* print flowTotal
    for (auto i = flowTotal.begin(); i != flowTotal.end(); i++){
        cout << i->first << " : " << i->second << endl;
    }
    */

}
/*
float packetScore(vector<int> flow){

    float score = 0;
    long firstSeen = flow[1];
    long lastSeen = flow[3];
    int protocol = flow[5];
    unsigned int dstIP = flow[14];
    int dstPort = flow[15];
    unsigned int flowSize = flow[23];

    int d = (lastSeen - firstSeen + 1)/30 +1;
    if ((lastSeen - firstSeen + 1) <= 0){
        return;
    }

    firstSeen = firstSeen - firstSeen%30;
    float bps = flowSize/d;
    int rob = rangeOfBytes(bps);

    // calculate a score of flow at period(firstSeen)
    // CLP(range of byte) + CLP(protocol) + CLP(dstIP) + CLP(dstPort).
    score = score + flowMap[firstSeen][rob] + protocolMap[firstSeen][protocol] + dstIPMap[firstSeen][dstIP] + dstPortMap[firstSeen][dstPort];

    return score;

}
*/

void readIP(unsigned int ts, unsigned int ip, int d){

    unsigned int prefix = ip - (ip % 65536);      // prefix /24
    // dstIPMap hasn't had this ts(key) yet
    /*if (dstIPMap.count(ts) == 0){
        dstIPMap[ts];
    }*/
    // dstIPMap[ts] hasn't had this ip(key) yet
   for(int i=0;i<d;i++)
   {
    if (dstIPMap[ts].count(prefix) == 0){
        dstIPMap[ts][prefix] = 0;
    }
    dstIPMap[ts][prefix]++;
    ts= ts+30;
   }

}

void readPort(unsigned int ts, int port,int d){

    // dstPortMap hasn't had this ts(key) yet
   /* if (dstPortMap.count(ts) == 0){
        dstPortMap[ts];
    }*/
    // dstPortMap[ts] hasn't had this port(key) yet
     for(int i=0;i<d;i++)
   {
    if (dstPortMap[ts].count(port) == 0){
        dstPortMap[ts][port] = 0;
    }
    dstPortMap[ts][port]++;
    ts=ts+30;
   }

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
  unsigned int flowSize = atoi(line+delimiters[22]);
  int dstPort = atoi(line+delimiters[14]); 
         int d = (lastSeen - firstSeen + 1)/30 +1;
       // vector<unsigned int> ts;
        if ((lastSeen - firstSeen + 1) <= 0){
            return;
        }
      /*  else if (d >= 1){
            for (int i = 0; i < d; i ++){
                ts.push_back(firstSeen + i);
            }
        }*/
        
        float bps = flowSize/d;
        auto mapp = constraintMap.equal_range(dstIP);
            for(auto i = mapp.first; i != mapp.second; i++){
                if (i->second >= firstSeen && i->second <= lastSeen){
                    return;
                }   
            }
     

        //for (int i = 0; i < d; i++){
        //    unsigned int timestamp = firstSeen + i;
                firstSeen = firstSeen - firstSeen%30;
                readSize(firstSeen, bps,d);
                readProtocol(firstSeen, protocol,d);
                readIP(firstSeen, dstIP,d);
                readPort(firstSeen, dstPort,d);
        //} 
 
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

// ------------------------------------------------------- profile

void flowProfilefn(map<unsigned int, map<float, float> > &flowMap){
    map<unsigned int, unsigned int> flowTotal;  // <ts, total>
    map<unsigned int, map<float, float> >::iterator i;
    map<float, float>::iterator j;
    for(i = flowMap.begin(); i != flowMap.end(); i++){
        if (flowTotal.count(i->first) == 0){
            flowTotal[i->first] = 0;
        }
        for(j = i->second.begin(); j != i->second.end(); j++){
            flowTotal[i->first] = flowTotal[i->first] + j->second;
        }
    }

    /* print flowTotal
    for (auto i = flowTotal.begin(); i != flowTotal.end(); i++){
        cout << i->first << " : " << i->second << endl;
    }
    */

   for(i = flowMap.begin() ; i != flowMap.end(); i++){
       for(j = i->second.begin(); j != i->second.end(); j++){
           flowMap[i->first][j->first] = j->second/flowTotal[i->first];
       }
   }

}

void protocolProfilefn(map<unsigned int, map<int, float> > &protocolMap){

    map<unsigned int, unsigned int> protocolTotal;  // <ts, total>
    map<unsigned int, map<int, float> >::iterator i;
    map<int, float>::iterator j;
    for(i = protocolMap.begin(); i != protocolMap.end(); i++){
        if (protocolTotal.count(i->first) == 0){
            protocolTotal[i->first] = 0;
        }
        for(j = i->second.begin(); j != i->second.end(); j++){
            protocolTotal[i->first] = protocolTotal[i->first] + j->second;
        }
    }

    /* print protocolTotal
    for (auto i = protocolTotal.begin(); i != protocolTotal.end(); i++){
        cout << i->first << " : " << i->second << endl;
    }
    */

   for(i = protocolMap.begin() ; i != protocolMap.end(); i++){
       for(j = i->second.begin(); j != i->second.end(); j++){
           protocolMap[i->first][j->first] = j->second/protocolTotal[i->first];
       }
   }

}

void dstIPProfilefn(map<unsigned int, map<unsigned int, float> > &dstIPMap){

    map<unsigned int, unsigned int> dstIPTotal;  // <ts, total>
    map<unsigned int, map<unsigned int, float> >::iterator i;
    map<unsigned int, float>::iterator j;
    for(i = dstIPMap.begin(); i != dstIPMap.end(); i++){
        if (dstIPTotal.count(i->first) == 0){
            dstIPTotal[i->first] = 0;
        }
        for(j = i->second.begin(); j != i->second.end(); j++){
            dstIPTotal[i->first] = dstIPTotal[i->first] + j->second;
        }
    }

    /* print dstIPTotal
    for (auto i = dstIPTotal.begin(); i != dstIPTotal.end(); i++){
        cout << i->first << " : " << i->second << endl;
    }
    */

   for(i = dstIPMap.begin() ; i != dstIPMap.end(); i++){
       for(j = i->second.begin(); j != i->second.end(); j++){
           dstIPMap[i->first][j->first] = j->second/dstIPTotal[i->first];
       }
   }

}

void dstPortProfilefn(map<unsigned int, map<int, float> > &dstPortMap){

    map<unsigned int, unsigned int> dstPortTotal;  // <ts, total>
    map<unsigned int, map<int, float> >::iterator i;
    map<int, float>::iterator j;
    for(i = dstPortMap.begin(); i != dstPortMap.end(); i++){
        if (dstPortTotal.count(i->first) == 0){
            dstPortTotal[i->first] = 0;
        }
        for(j = i->second.begin(); j != i->second.end(); j++){
            dstPortTotal[i->first] = dstPortTotal[i->first] + j->second;
        }
    }

    /* print dstPortTotal
    for (auto i = dstPortTotal.begin(); i != dstPortTotal.end(); i++){
        cout << i->first << " : " << i->second << endl;
    }
    */

   for(i = dstPortMap.begin() ; i != dstPortMap.end(); i++){
       for(j = i->second.begin(); j != i->second.end(); j++){
           dstPortMap[i->first][j->first] = j->second/dstPortTotal[i->first];
       }
   }

}

// -------------------------------------------------------

// ------------------------------------------------------- print 

void printConstraintMap(multimap<unsigned int, unsigned int> mapp){
    
    multimap<unsigned int, unsigned int>::iterator i;
    for(i = mapp.begin(); i != mapp.end(); i++){
        cout << i->first << " : " << i->second << endl;
    }

}

void printFlowMap(map<unsigned int, map<float, float> > mapp){

  
    map<unsigned int, map<float, float> >::iterator i;
    map<float, float>::iterator j;

    for(i = mapp.begin(); i != mapp.end(); i++){
        cout << i->first << endl;
        for(j = i->second.begin(); j != i->second.end(); j++){
         cout << "R " << j->first << " " << std::setprecision(2)<< j->second << endl;
        /*    if(j->second > arr[(int)j->first])
            {

               arr[(int)j->first] = j->second;
               ts[(int)j->first] = i->first;
            }    */
        }
    }



}

void printProtocolMap(map<unsigned int, map<int, float> > mapp){

    map<unsigned int, map<int, float> >::iterator i;
    map<int, float>::iterator j;
    for(i = mapp.begin(); i != mapp.end(); i++){
        cout << i->first << endl;
        for(j = i->second.begin(); j != i->second.end(); j++){
            cout << "P " << j->first << " "<< std::setprecision(2) << j->second << endl;
        }
    }

}

void printIPMap(map<unsigned int, map<unsigned int, float> > mapp){

    map<unsigned int, map<unsigned int, float> >::iterator i;
    map<unsigned int, float>::iterator j;
    for(i = mapp.begin(); i != mapp.end(); i++){
        cout << i-> first << endl;
        for(j = i->second.begin(); j != i->second.end(); j++){
            cout << "I " << j->first << " " << std::setprecision(2)<< j->second << endl;
        }
    }

}

void printPortMap(map<unsigned int, map<int, float> > mapp){

    map<unsigned int, map<int, float> >::iterator i;
    map<int, float>::iterator j;
    for(i = mapp.begin(); i != mapp.end(); i++){
        cout << i->first << endl;
        for(j = i->second.begin(); j != i->second.end(); j++){
            cout << "T " << j->first << " " << std::setprecision(2)<< j->second << endl;
        }
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
  readProfile();
  cout<<endl<<"Done reading trained profile \n";

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
            //auto t2 = std::chrono::high_resolution_clock::now();
            //  auto duration = std::chrono::duration_cast<std::chrono::microseconds>( t2 - t1 ).count();

            //std::cout << duration<<endl;

	  }

/*    flowProfile(flowMap);
    protocolProfile(protocolMap);
    dstIPProfile(dstIPMap);
    dstPortProfile(dstPortMap);
    printFlowMap(flowMap);
    printProtocolMap(protocolMap);
    printIPMap(dstIPMap);
    printPortMap(dstPortMap);*/
	cout<<"Done with the file "<<file<<" time "<<time(0)<<endl;
	pclose(nf);
      }
    flowProfilefn(flowMap);
    protocolProfilefn(protocolMap);
    dstIPProfilefn(dstIPMap);
    dstPortProfilefn(dstPortMap);
    cout<<"=========FLOWS========="<<endl;
    printFlowMap(flowMap);
     cout<<"=========PROTO========="<<endl;
    printProtocolMap(protocolMap);
     cout<<"=========DSTS========="<<endl;
    printIPMap(dstIPMap);
      cout<<"=========PORT========="<<endl;
    printPortMap(dstPortMap);

      //print_res();
    }
  return 0;
}
