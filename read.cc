/* Copyright 2008, 2010, Oracle and/or its affiliates. All rights reserved.

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; version 2 of the License.

There are special exceptions to the terms and conditions of the GPL
as it is applied to this software. View the full text of the
exception in file EXCEPTIONS-CONNECTOR-C++ in the directory of this
software distribution.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
*/

/* Standard C++ includes */
#include <stdlib.h>
#include <iostream>
#include <sstream>

/*
  Include directly the different
  headers from cppconn/ and mysql_driver.h + mysql_util.h
  (and mysql_connection.h). This will reduce your build time!
*/
#include <mysql_connection.h>
#include <cppconn/driver.h>
#include <cppconn/exception.h>
#include <cppconn/resultset.h>
#include <cppconn/statement.h>
#include <cppconn/prepared_statement.h>
#include <streambuf>

using namespace std;

class DataBuf : public streambuf
{
public:
  DataBuf(char * d, size_t s) {
    setg(d, d, d + s);
  }
};

int main(void)
{
  cout << endl;

  try {
    sql::Driver *driver;
    sql::Connection *con;
    sql::PreparedStatement *pstmt;
    sql::Statement *stmt;
    
    /* Create a connection */
    driver = get_driver_instance();
    con = driver->connect("tcp://127.0.0.1:3306", "root", "steelmysql");
    /* Connect to the MySQL test database */
    con->setSchema("amon");
    int bricks[128*128];

    try
      {
	stmt = con->createStatement();
	string query="SELECT * from databricks where trace='chargen' order by timestamp asc";
	sql::ResultSet* rset = stmt->executeQuery(query.c_str()); //"SELECT timestamp,databrick from records");
	cout << " Executed query " << rset->rowsCount()<<endl;
	while (rset->next()) {
	  /* Access column data by alias or column name */
	  char* token;
	  long int tstamp = strtol(rset->getString("timestamp").c_str(), &token, 10);
	  cout<<"Time "<<tstamp<<endl;
	  string out1 = rset->getString("volume");
	  int* outv = (int*) out1.c_str();
	  string out2 = rset->getString("symmetry");
	  int* outs = (int*) out2.c_str();
	  cout << " Time "<<tstamp<<endl;
	  for (int i=0;i<128*128;i++)
	    cout<<tstamp<<" bin="<<i<< " value is " << outv[i] <<" "<<outs[i]<< "\n";
	  cout << endl;
	  //rstream >> outm;
	}
      }
    catch (sql::SQLException &e) {
      cout << "# ERR: SQLException in " << __FILE__;
      cout << "# ERR: " << e.what();
      cout << " (MySQL error code: " << e.getErrorCode();
      cout << ", SQLState: " << e.getSQLState() << " )" << endl;
    }
    delete stmt;
    delete con;

  } catch (sql::SQLException &e) {
    cout << "# ERR: SQLException in " << __FILE__;
    cout << "# ERR: " << e.what();
    cout << " (MySQL error code: " << e.getErrorCode();
    cout << ", SQLState: " << e.getSQLState() << " )" << endl;
  }

  cout << endl;

  return EXIT_SUCCESS;
}
