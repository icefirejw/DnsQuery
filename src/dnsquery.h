#ifndef __DNS_QUERY__
#define __DNS_QUERY__

#include <cstdlib>
#include <iostream>
#include <windows.h>
#include <winsock2.h>

//#define DNSDBG 
#define BUFLEN 65535
#define DNS_SELECT_TIMEOUT 1   //receive packets timeout is 1 seconds;
#define DNS_TRY_TIMES      3    //try times
#define NAMESERVER_NUMBER 3 //name server numbers;
#define DNS_ERR_TIMEOUT   -123321;

#define DNS_PORT 53 //dns port 

#define DNS_GET_RR_NAME 0x01
#define DNS_GET_RR_DATA 0x02

//Type field of Query and Answer
#define T_A         1       /* host address */
#define T_NS        2       /* authoritative server */
#define T_CNAME     5       /* canonical name */
#define T_SOA       6       /* start of authority zone */
#define T_PTR       12      /* domain name pointer */
#define T_MX        15      /* mail routing information */


/* 
DNS Message Format
+---------------------+
|        Header                       |
+---------------------+
|       Question                     | the question for the name server
+---------------------+
|        Answer                       | RRs answering the question
+---------------------+
|      Authority                      | RRs pointing toward an authority
+---------------------+
|      Additional                     | RRs holding additional information
+---------------------+
*/

/************             DNS HEADER        **************************
                                                                  1    1    1    1    1    1
  0     1    2    3     4    5    6    7     8    9     0    1    2    3    4    5
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                                ID                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|QR|   Opcode  |AA|TC |RD|RA|   Z     |   RCODE                      |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                           QDCOUNT                                                        |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                          ANCOUNT                                                         |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                          NSCOUNT                                                         |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                           ARCOUNT                                                         |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*************************************************************/
struct DNS_HEADER
{
    unsigned    short id;            // identification number
    
    unsigned    char rd     :1;        // recursion desired
    unsigned    char tc     :1;        // truncated message
    unsigned    char aa     :1;        // authoritive answer
    unsigned    char opcode :4;        // purpose of message
    unsigned    char qr     :1;        // query/response flag
    
    unsigned    char rcode  :4;        // response code
    unsigned    char cd     :1;        // checking disabled
    unsigned    char ad     :1;        // authenticated data
    unsigned    char z      :1;        // its z! reserved
    unsigned    char ra     :1;        // recursion available
    
    unsigned    short q_count;       // number of question entries
    unsigned    short ans_count;     // number of answer entries
    unsigned    short auth_count;    // number of authority entries
    unsigned    short add_count;     // number of resource entries
};

/** DNS Question Format  
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                                                                                   |
/                     QNAME                                                                   /
/                                                                                                    /
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     QTYPE                                                                   |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     QCLASS                                                                 |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+  **/
struct QUESTION
{
    unsigned short qtype;
    unsigned short qclass;
};

/* 
Resource record format
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                                                                                  |
/                                                                                                   /
/                      NAME                                                                    /
|                                                                                                  |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      TYPE                                                                     |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     CLASS                                                                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      TTL                                                                        |
|                                                                                                   |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                   RDLENGTH                                                                |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
/                     RDATA                                                                    /
/                                                                                                   /
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

In order to reduce the size of messages, the domain system utilizes a 
compression scheme which eliminates the repetition of domain names in a
message. In this scheme, an entire domain name or a list of labels at
the end of a domain name is replaced with a pointer to a prior occurance
of the same name.
The pointer takes the form of a two octet sequence: 
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
| 1     1 |                                       OFFSET                                   |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

The OFFSET field specifies an offset from the start of the message 
(i.e., the first octet of the ID field in the domain header)
*///for message parse
struct  RR_DATA
{
    unsigned short type;   //two octets containing one of the RR TYPE codes
    unsigned short _class;
    unsigned int   ttl;     
    unsigned short rdlen;    // length of rdata
};
#define DNS_OFFSET_MASK       0xC0 //1100
#define DNS_RR_DATA_HEAD_SIZE (3*sizeof(unsigned short)+ sizeof(unsigned int))

using namespace std;
struct DNS_QUESTION
{
    unsigned char* qname;
    unsigned short qtype;
    unsigned short qclass;    
};

struct  DNS_RRS_DATA
{
    unsigned char* name;
    unsigned short type;   
    unsigned short _class;
    unsigned int   ttl;     
    unsigned short rdlen;
    unsigned char* r_data;
};

struct DNS_QUERY
{
    struct DNS_HEADER DnsHeader;
    struct DNS_QUESTION DnsQuestion;
    struct DNS_RRS_DATA *DnsAnswer;
    struct DNS_RRS_DATA *Authority;
    struct DNS_RRS_DATA *Additional;
};

class DnsQuery
{
    struct DNS_QUERY DnsQueryData;
    int DNS_DBG;
    
    private:
    int ChangeHostToNetFormat(string hostname, unsigned char* dnsformat);
    int ChangeNetToHostFormat(unsigned char* name);
    unsigned int ReadRRName(int flag, unsigned char* pread, const unsigned char* message, struct DNS_RRS_DATA* rrs_data);    
    int ParseDnsBuf(const unsigned char* message);
    int GetDnsRRContent(unsigned char* pread, const unsigned char* message, struct DNS_RRS_DATA* rrs_data);
    void DnsQuery::PrintDnsRRContent(struct DNS_RRS_DATA* rrs_data);
    void DnsQuery::ReleaseRRContent(struct DNS_RRS_DATA* rrs_data);
    
    public:
    DnsQuery(void)
    {
        DNS_DBG = 0;
        DnsQueryData.DnsQuestion.qname = NULL;
        DnsQueryData.DnsAnswer = NULL;
        DnsQueryData.DnsHeader.ans_count = 0;
        DnsQueryData.Authority = NULL;
        DnsQueryData.DnsHeader.auth_count = 0;
        DnsQueryData.Additional = NULL;;
        DnsQueryData.DnsHeader.auth_count = 0;
    };
    
    ~DnsQuery(void)
    {
        ReleaseDnsQuery();
    };
    
    int GetHostByName(const string hostname);
    int GetHostByNameWithNS(const string hostname, const string nameserver);
    string GetNameserver(int index);
    int SetNameserver(int index, const string nameserver);
    void DnsQuery::PrintDnsResult(void);
    void DnsQuery::ReleaseDnsQuery(void);
    void DnsQuery::EnableDnsQuery(void);
    void DnsQuery::DisableDnsQuery(void);
};

#endif
