//================================================================================//
//================================================================================//
/*
 *
 * (C) 2017 - Jelena Mirkovic <sunshine@isi.edu>
 *           
 *           
 *           
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU LESSER GENERAL PUBLIC LICENSE
 * published by the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 * 
 */
//================================================================================//
//================================================================================//


#include <iostream>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <iostream>
#include <sstream>
#include <fstream>
#include <string>

#include "mysql_connection.h"

#include <cppconn/driver.h>
#include <cppconn/exception.h>
#include <cppconn/resultset.h>
#include <cppconn/statement.h>
#include <cppconn/prepared_statement.h>
#include <streambuf>

#include "haship.h"
#include "haship.c"
#include "bm_structs.h"
#include <openssl/sha.h>


#define ATTACK_THRESH 12 /* Make this a configurable param */
#define HIST_LEN 1000    /* How long we remember history */
#define MAX_NUM_DEVS 64
#define MAXLEN 128
#define CONFIG_FILE "amon.config"
#define VERBOSE_SUPPORT
#define MAX_LINE 255
#define TCP 6
#define UDP 17
#define BUF_SIZE 1000
#define AR_LEN 30
#define MIN_SAMPLES 1000

sql::Connection *con;
sql::Statement *stmt;
sql::ResultSet *res;
int interval=3;

using namespace std;

class DataBuf : public streambuf
{
public:
  DataBuf(char * d, size_t s) {
    setg(d, d, d + s);
  }
};


//====================================================//
//===== Function to trim strings for config file =====//
//====================================================//
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

struct flow_p
{
  long time;
  int len;
  int oci;
  flow_t flow;
};

int *dst[2];                /* current volume and symmetry per dst */
int is_attack[BRICK_DIMENSION];
int is_abnormal[BRICK_DIMENSION]; 
ofstream outfiles[BRICK_DIMENSION];

/* Types of statistics. If this changes, update the entire section */
enum period{cur, hist};
enum type{n, avg, ss};
enum dim{vol, sym};
double stats[2][3][2][BRICK_DIMENSION]; /* statistics for attack detection, 
first dim - CUR, HIST, second dim - N, AVG, SS, third dim - VOL, SYM */

struct record
{
  unsigned int timestamp;
  double avgv;
  double avgs;
  double stdv;
  double stds;
  double valv;
  double vals;
};
/* Circular array of records so that when we detect attacks we 
   can generate useful info */
record records[HIST_LEN][BRICK_DIMENSION];
int ri=0;

/* This is just for rounds of moving current measures to past */
int samples = 0;
int tot_samples = 0;

struct conf_param {
  char user[MAXLEN];
  char pass[MAXLEN];
  char db_client[MAXLEN];
  char database[MAXLEN];
  char db_collection[MAXLEN];
}
conf_param;
struct conf_param parms;

//=====================================================//
//===== Function to parse strings for config file =====//
//=====================================================//
void
parse_config (struct conf_param * parms)
{
  char *s, buff[256];
  FILE *fp = fopen (CONFIG_FILE, "r");
  if (fp == NULL)
  {
    printf ("\n Config file %s does not exist. Please include it and re-run.. \n",CONFIG_FILE);
    exit (0);
  }
  printf ("\n Reading config file %s ...",CONFIG_FILE);
  while ((s = fgets (buff, sizeof buff, fp)) != NULL)
  {
        /* Skip blank lines and comment lines */
        if (buff[0] == '\n' || buff[0] == '#')
          continue;

        /* Parse name/value pair from line */
        char name[MAXLEN], value[MAXLEN];
        memset(name, '\0', sizeof(name));
        memset(value, '\0', sizeof(value));
        s = strtok (buff, "=");
        if (s==NULL)
          continue;
        else
        {  strcpy (name, s);
           trim (name);
        } 
        s = strtok (NULL, "=");
        if (s==NULL)
          continue;
        else
        {
          strcpy (value, s);
          trim (value);
        }

        /* Copy into correct entry in parameters struct */
        if ( strcasecmp(name, "mongo_db_client")==0 ||  strcasecmp(name, "db_client")==0)
        {
          strncpy (parms->db_client, value, MAXLEN);
        }
	else if ( strcasecmp(name, "user")==0)
        {
          strncpy (parms->user, value, MAXLEN);
        }
	else if ( strcasecmp(name, "pass")==0)
        {
          strncpy (parms->pass, value, MAXLEN);
        }
        else if ( strcasecmp(name, "database")==0)
        {
          strncpy (parms->database, value, MAXLEN);
        }
        else if ( strcasecmp(name, "db_collection")==0)
        {
          strncpy (parms->db_collection, value, MAXLEN);
        }
	else
        {  printf ("WARNING: %s/%s: Unknown name/value pair!\n",
           name, value);
        }
  }

  fclose (fp);
}


int training_done = 0;

int max(int a, int b)
{
  if (a>b)
    return a;
  else
    return b;
}

void update_dst_arrays()
{
  if (training_done)
    {
      for (int i=0;i<BRICK_DIMENSION;i++)
	{
	  for (int j=vol; j<=sym; j++)
	    {
	      /* Only update if everything looks normal */
	      if (!is_abnormal[i])
		{
		  // Update avg and ss
		  stats[cur][n][j][i] += 1;
		  if (stats[cur][n][j][i] == 1)
		    {
		      stats[cur][avg][j][i] =  dst[j][i];
		      stats[cur][ss][j][i] =  0;
		    }
		  else
		    {
		      int ao = stats[cur][avg][j][i];
		      stats[cur][avg][j][i] = stats[cur][avg][j][i] + (dst[j][i] - stats[cur][avg][j][i])/stats[cur][n][j][i];
		      stats[cur][ss][j][i] = stats[cur][ss][j][i] + (dst[j][i]-ao)*(dst[j][i] - stats[cur][avg][j][i]);
		    }		
		}
	    }
	}
    }
  samples++;
  tot_samples++;
  if (samples == MIN_SAMPLES)
    {
      if(!training_done)
	{
	  cout<<"Training is done"<<endl;
	  training_done = 1;
	}
      else
	{
	  for (int j = n; j <= ss; j++)
	    for (int k = vol; k <= sym; k++)
	      {
		// Move cur arrays into hist and zero down cur
		memcpy (stats[hist][j][k], stats[cur][j][k], BRICK_DIMENSION * sizeof (double));
		memset ((double*)stats[cur][j][k], 0, BRICK_DIMENSION * sizeof (double));
	      }
	}
      samples = 0;
    }
  // Zero down dst summaries for the next round
  for (int i=vol; i<=sym;i++)
    memset ((int *) dst[i], 0, BRICK_DIMENSION * sizeof (int));
}

//=================================================================//
//===== Function to detect values higher than mean + 5 * stdev ====//
//=================================================================//
int abnormal(int type, int index, unsigned int timestamp)
{
  double mean = stats[hist][avg][type][index];
  double std = sqrt(stats[hist][ss][type][index]/(stats[hist][n][type][index]-1));

  if (type == vol && dst[type][index] > mean + 5*std)
    return 1;
  else if (type == sym && (dst[type][index] > mean + 5*std || dst[type][index] < mean - 5*std))
    return 1;
  else
    return 0;
}


void detect_attack(unsigned int timestamp)
{
  for (int i=0;i<BRICK_DIMENSION;i++)
    {
      double avgv = stats[hist][avg][vol][i];
      double stdv = sqrt(stats[hist][ss][vol][i]/(stats[hist][n][vol][i]-1));
      double avgs = stats[hist][avg][sym][i];
      double stds = sqrt(stats[hist][ss][sym][i]/(stats[hist][n][sym][i]-1));

      records[ri][i].timestamp = timestamp;
      records[ri][i].avgv = avgv;     
      records[ri][i].avgs = avgs;
      records[ri][i].stdv = stdv;
      records[ri][i].stds = stds;
      records[ri][i].valv = dst[vol][i];
      records[ri][i].vals = dst[sym][i];
	
      if (training_done && abnormal(vol, i, timestamp) && abnormal(sym, i, timestamp))
	{
	  if (!is_attack[i])
	    is_abnormal[i] ++;
	  if (is_abnormal[i] > ATTACK_THRESH && is_attack[i] == 0)
	    {
	      /* Signal attack detection */
	      //is_attack = 1;
	      is_attack[i] = 1;
	      /* Dump records into a file */
	      cout <<" Attack detected in destination bin " << i << " time " << timestamp << " samples "<<tot_samples<<" mean "<<avgv<<" + 5*"<< stdv<<" < "<<dst[vol][i]<<" and "<<avgs<<" +- 5*"<<stds<<" inside "<<dst[sym][i]<<" flag "<<is_attack[i]<<endl;
	      char filename[MAXLEN];
	      sprintf(filename,"%d.log.%u", i, timestamp);
	      outfiles[i].open(filename);
	      for (int j = ri+1; j != ri; j++)
		{
		  if (records[j][i].timestamp > 0)
		    {
			  outfiles[i] <<records[j][i].timestamp<<" "<<records[j][i].avgv<<" ";
			  outfiles[i] <<records[j][i].stdv<<" "<<records[j][i].valv<<" ";
			  outfiles[i] <<records[j][i].avgs<<" "<<records[j][i].stds<<" ";
			  outfiles[i] <<records[j][i].vals<<" 0"<<endl;
			}
		      if (j == HIST_LEN)
			j = 0;
		    }
		  outfiles[i] <<records[ri][i].timestamp<<" "<<records[ri][i].avgv<<" ";
		  outfiles[i] <<records[ri][i].stdv<<" "<<records[ri][i].valv<<" ";
		  outfiles[i] <<records[ri][i].avgs<<" "<<records[ri][i].stds<<" ";
		  outfiles[i] <<records[ri][i].vals<<" 1"<<endl;
		}
	}
      else if (training_done && !abnormal(vol, i, timestamp) && !abnormal(sym, i, timestamp))
	{
	  if (is_abnormal[i] > 0)
	    is_abnormal[i] --;
	  if (is_attack[i] > 0 && is_abnormal[i] == 0)
	    {
	      /* Signal end of attack */
	      cout <<" Attack has stopped in destination bin "<< i << " time " << timestamp << " samples "<<tot_samples<<endl;
	      is_attack[i] = 0;
	    }
	}
    }
  ri++;
  if (ri == HIST_LEN)
    ri = 0;
}

//==========================================================//
//=================== Read Databricks from DB ==============//
//==========================================================//
void read_from_db ()
{
  sql::Statement *stmt = con->createStatement();
  char query[256];
 
  sprintf(query, "SELECT * from records order by timestamp asc");
  sql::ResultSet* rset = stmt->executeQuery(query);
  // Read existing data, create destination array and update
  // what is there
  while (rset->next()) {
	/* Access column data by alias or column name */
	char* token;
	long int timestamp = strtol(rset->getString("timestamp").c_str(), &token, 10);
	string out = rset->getString("volume");
	unsigned int* outp = (unsigned int*) out.c_str();
	for (int i=0;i<BRICK_DIMENSION;i++)
	  for (int j=0;j<BRICK_DIMENSION;j++)
	    dst[vol][i] += outp[j*BRICK_DIMENSION+i];
	out = rset->getString("symmetry");
	int* outs = (int*) out.c_str();
	for (int i=0;i<BRICK_DIMENSION;i++)
	  for (int j=0;j<BRICK_DIMENSION;j++)
	    dst[sym][i] += outs[j*BRICK_DIMENSION+i];

	if (training_done)
	  detect_attack(timestamp);	
	else
	  {
	    // Collect data for training
	    for (int i=0;i<BRICK_DIMENSION;i++)
	      {
		for (int j=vol; j<=sym; j++)
		  {
		    // Update avg and ss
		    stats[hist][n][j][i] += 1;
		    if (stats[hist][n][j][i] == 1)
		    {
		      stats[hist][avg][j][i] =  dst[j][i];
		      stats[hist][ss][j][i] =  0;
		      
		      if (i==50 && j==sym)
			cout<<"First "<<timestamp<<" avg "<< stats[hist][avg][j][i] <<" stdev 0 value "<<dst[j][i]<<endl;
		    }
		    else
		      {
			int ao = stats[hist][avg][j][i];
			stats[hist][avg][j][i] = stats[hist][avg][j][i] + (dst[j][i] - stats[hist][avg][j][i])/stats[hist][n][j][i];
			stats[hist][ss][j][i] = stats[hist][ss][j][i] + (dst[j][i]-ao)*(dst[j][i] - stats[hist][avg][j][i]);
			if (i==50 && j==sym)
			  cout<<"Training "<<timestamp<<" avg "<<stats[hist][avg][j][i]<<" stdev "<<sqrt(stats[hist][ss][j][i]/(stats[hist][n][j][i]-1))<<" value "<<dst[j][i]<<" samples "<<stats[hist][n][j][i]<<endl;
		      }
		  }
	      }
	  }
	update_dst_arrays();
  }
  stmt->close();
  delete rset;
  delete stmt;
}


/***************************************************************************/

void
printHelp (void)
{
  printf ("detect\n(C) 2017 USC/ISI.\n\n");
  printf ("-h              Print this help\n");
}

int main (int argc, char *argv[])
{
  parse_config (&parms);                /* Read config file */
  
  sql::Driver *driver;
  
  /* Create a connection */
  driver = get_driver_instance();
  con = driver->connect(parms.db_client, parms.user, parms.pass);
  con->setSchema(parms.database);
  
  /* Initialize variables and structs */
  for (int i = vol; i <= sym; i++)
    {
      dst[i] = (int *) malloc(BRICK_DIMENSION * sizeof (int));
      memset ((int *) dst[i], 0, BRICK_DIMENSION * sizeof (int));
    }
  memset ((int *) is_attack, 0, BRICK_DIMENSION * sizeof (int));
  memset ((int *) is_abnormal, 0, BRICK_DIMENSION * sizeof (int));
  for (int i = cur; i <= hist; i++)
    for (int j = n; j <= ss; j++)
      for (int k = vol; k <= sym; k++)
	    memset ((double *) stats[i][j][k], 0, BRICK_DIMENSION * sizeof (double));

  read_from_db();
  return (0);
}
