#include "dnsquery.h"


int DnsQuery::GetHostByNameWithNS(const string hostname, const string nameserver)
{
    WSADATA firstsock;
    SOCKET  s;
    struct sockaddr_in a;
    struct sockaddr_in dest;
    
    struct DNS_HEADER *dns = NULL;
    struct QUESTION   *qinfo = NULL;
    unsigned char* tmpbuf;
    unsigned char* qname;
    unsigned int sendbuflen = 0;
    int destlen;
    int i;    
    int errerno = 0;

    struct timeval loWaitTime = {DNS_SELECT_TIMEOUT, 0};
    fd_set SockFd; 
    int iReady;

    if (DNS_DBG == 1){
        cout <<endl;
        cout << "Solving the hostname:"<<hostname<<", with name server:"<< nameserver << endl;
    }
    if (WSAStartup(MAKEWORD(2,2),&firstsock) != 0) {        
        errerno = -1;
        goto QUERYERROR;
    }

    tmpbuf = new unsigned char[BUFLEN];
    if (NULL == tmpbuf) {
        errerno = -2;
        goto QUERYERROR;
    }
    
    if (DNS_DBG == 1)
        cout << "Prepare sending dns request..." << endl;

    s = socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);  //UDP packet for DNS queries
    
    dest.sin_family = AF_INET;
    dest.sin_port = htons(DNS_PORT);
    dest.sin_addr.s_addr = inet_addr(nameserver.c_str());  //dns servers

    //Set the DNS structure to standard queries
    dns = (struct DNS_HEADER *)tmpbuf;
    
    dns->id = (unsigned short) htons(GetCurrentProcessId());
    dns->qr = 0;      //This is a query
    dns->opcode = 0;  //This is a standard query
    dns->aa = 0;      //Not Authoritative
    dns->tc = 0;      //This message is not truncated
    dns->rd = 1;      //Recursion Desired
    dns->ra = 0;      //Recursion not available! hey we dont have it (lol)
    dns->z  = 0;
    dns->ad = 0;
    dns->cd = 0;
    dns->rcode = 0;
    dns->q_count = htons(1);   //we have only 1 question
    dns->ans_count  = 0;
    dns->auth_count = 0;
    dns->add_count  = 0;

    sendbuflen += sizeof(struct DNS_HEADER);
        
    //point to the query portion
    qname = tmpbuf + sendbuflen;
    ChangeHostToNetFormat(hostname, qname);
    sendbuflen = sendbuflen + strlen((char*)qname) + 1; // '\0'
    
    qinfo  = (struct QUESTION*)(tmpbuf + sendbuflen); 
    qinfo->qtype = htons(1); // ipv4 request
    qinfo->qclass = htons(1); //internet
    sendbuflen += sizeof(struct QUESTION);
    
    if (DNS_DBG == 1)
        cout << "Sending dns request, datalen=" << sendbuflen << "...";

    if (SOCKET_ERROR == sendto(s, (char*)tmpbuf, sendbuflen, 0, (struct sockaddr*)&dest, sizeof(dest))){
        errerno = -3;
        goto QUERYERROR;
    }
    if (DNS_DBG == 1)
        cout << " Successfully." << endl;

    destlen = sizeof(dest);
    if (DNS_DBG == 1)
        cout<<"Receiving answer...";
    
    for (i = 0; i <DNS_TRY_TIMES; i++) {
        FD_ZERO(&SockFd); 
        FD_SET(s, &SockFd); 
        iReady = select(s+1, &SockFd, NULL, NULL, &loWaitTime); 
        if (iReady < 0) {
            errerno = -4;
            goto QUERYERROR;

        } 
        else if (iReady = 0) 
            continue;
        else 
            break;
    }
    
    if (i >= DNS_TRY_TIMES){
        errerno = DNS_ERR_TIMEOUT;
        goto QUERYERROR;       
    }

    if (FD_ISSET(s,&SockFd)){
        if(SOCKET_ERROR == recvfrom (s,(char*)tmpbuf,BUFLEN,0,(struct sockaddr*)&dest,&destlen)) {
            errerno = -5;
            goto QUERYERROR;
        }
    } else {
        errerno = -6;
        goto QUERYERROR;    
    }
    
    if (DNS_DBG == 1)
        cout<<"Successfully."<<endl;
    
    if (ParseDnsBuf(tmpbuf)<0){
        errerno = -7;
        goto QUERYERROR;  
    }
    
    if (tmpbuf != NULL) delete [] tmpbuf;
    WSACleanup();
    
    return errerno;

QUERYERROR:
    if (DNS_DBG == 1)
        cout << "Failed. Errerno:" <<errerno<<". Error Code:" <<WSAGetLastError()<<endl;
    
    if (tmpbuf != NULL) delete [] tmpbuf;
   
    return errerno;
    
}

//this will convert 'www.google.com' to '3www6google3com'
//convert 'www.sina.com.cn' to '3www4sina3com2cn' 
int DnsQuery::ChangeHostToNetFormat(string hostname, unsigned char *dnsformat)
{
    unsigned char* host;
    int i;
    int lock = 0;

    hostname.append(".");

    host = (unsigned char*)hostname.c_str();
    
    if (NULL == host || NULL == dnsformat) return -1;
    
    for (i=0; i<strlen((char*)host); i++) {
        if ('.' == host[i]){
            *dnsformat++ = i-lock;
            for (;lock<i;lock++){
                *dnsformat++ = host[lock];
            }
            lock=i+1;
        }
    }
    *dnsformat = '\0'; //end of string
    
    return 0;
}

int DnsQuery::ChangeNetToHostFormat(unsigned char *name)
{
    unsigned int p;
    int i,j;
    
    //now convert 3www6google3com0 to www.google.com
    for(i=0; i<(int)strlen((const char*)name); i++)
    {
        p = name[i];
        for(j=0; j<p; j++)
        {
            name[i]=name[i+1];
            i=i+1;
        }
        name[i]='.';
    }
    name[i-1]='\0';      //remove the last dot
}

string DnsQuery::GetNameserver(int index)
{
    
}

int DnsQuery::SetNameserver(int index, const string nameserver)
{
    return 0;
}

int DnsQuery::GetDnsRRContent(unsigned char* pread, const unsigned char* message, struct DNS_RRS_DATA* rrs_data)
{   
    unsigned int p; // read the buffer position
    struct RR_DATA* rr_data;
    unsigned char* content;
    int j;
    
    content = pread;
    if (content == NULL) return 0;

    p = ReadRRName(DNS_GET_RR_NAME, content, message, rrs_data);
    content = pread + p;

    rr_data = (struct RR_DATA*)content;        
    rrs_data->type = ntohs(rr_data->type);
    rrs_data->_class = ntohs(rr_data->_class);
    rrs_data->ttl = ntohl(rr_data->ttl);
    rrs_data->rdlen = ntohs(rr_data->rdlen);
    p += DNS_RR_DATA_HEAD_SIZE;       
    content = pread + p;

    if (rrs_data->type == T_A){ // ip address
        rrs_data->r_data = new unsigned char[rrs_data->rdlen];
        for (j=0; j<rrs_data->rdlen; j++) 
            rrs_data->r_data[j] = content[j];
        rrs_data->r_data[rrs_data->rdlen] = '\0';
        p += rrs_data->rdlen;  
        content = pread + p;
    } else { 
        p += ReadRRName(DNS_GET_RR_DATA, content, message, rrs_data);
        content = pread + p;
    }

    return p;
}

void DnsQuery::PrintDnsRRContent(struct DNS_RRS_DATA* rrs_data)
{
    int i = 0;
    cout<<"  Name: "<<rrs_data->name<<endl;
    cout<<"  Type: "<<rrs_data->type<<endl;
    cout<<"  Class: "<<rrs_data->_class<<endl;
    cout<<"  Time to live: "<<rrs_data->ttl<<endl;
    cout<<"  Data length: "<<rrs_data->rdlen<<endl;
    cout<<"  Data : ";
    if (rrs_data->type == T_A){
        for (i=0; i<rrs_data->rdlen-1; i++)
            cout<<(int)(rrs_data->r_data[i])<<".";
        cout<<(int)(rrs_data->r_data[rrs_data->rdlen-1])<<endl;
    }
    else
        cout<<rrs_data->r_data<<endl;   
}

void DnsQuery::PrintDnsResult(void)
{
    unsigned int i;
    struct DNS_RRS_DATA* rrs_data;
    
    cout<<endl;
    cout<<"The response contains : "<<endl;
    cout<<"  " << DnsQueryData.DnsHeader.q_count<< " Questions." << endl;
    cout<<"  " << DnsQueryData.DnsHeader.ans_count << " Answers." << endl;
    cout<<"  " << DnsQueryData.DnsHeader.auth_count << " Authoritative Servers." << endl;
    cout<<"  " << DnsQueryData.DnsHeader.add_count << " Additional records." << endl;
    cout<<endl;
    cout<<"The response query:"<<endl;
    cout<<"  Name: "<<DnsQueryData.DnsQuestion.qname<<endl;
    cout<<"  Type: "<<DnsQueryData.DnsQuestion.qtype<<endl;
    cout<<"  Class: "<<DnsQueryData.DnsQuestion.qclass<<endl;
    
    cout<<endl;
    cout<<"The response answers:"<<endl;
    for (i=0;i<DnsQueryData.DnsHeader.ans_count;i++){
        rrs_data = &DnsQueryData.DnsAnswer[i];
        PrintDnsRRContent(rrs_data);
    }
    
    cout<<endl;
    cout<<"The response authorities:"<<endl;
    for (i=0;i<DnsQueryData.DnsHeader.auth_count;i++){
        rrs_data = &DnsQueryData.Authority[i];
        PrintDnsRRContent(rrs_data);
    }

    cout<<endl;
    cout<<"The response additional:"<<endl;
    for (i=0;i<DnsQueryData.DnsHeader.add_count;i++){
        rrs_data = &DnsQueryData.Additional[i];
        PrintDnsRRContent(rrs_data);
    }

}
int DnsQuery::ParseDnsBuf(const unsigned char* message)
{
    struct DNS_HEADER *dns = NULL;
    struct QUESTION   *qinfo = NULL;
    struct RR_DATA    *rr_data = NULL;
    unsigned char* qname;
    unsigned char* pread;
    unsigned int i,j,q_count,ans_count,auth_count,add_count,qnamelen;
    unsigned int p; // read the buffer position
    
    dns=(struct DNS_HEADER*)message;    
    
    DnsQueryData.DnsHeader = *dns;    
    DnsQueryData.DnsHeader.id = ntohs(dns->id);
    q_count = ntohs(dns->q_count);
    DnsQueryData.DnsHeader.q_count = q_count;
    ans_count = ntohs(dns->ans_count); 
    DnsQueryData.DnsHeader.ans_count = ans_count;
    auth_count = ntohs(dns->auth_count); 
    DnsQueryData.DnsHeader.auth_count = auth_count;
    add_count = ntohs(dns->add_count); 
    DnsQueryData.DnsHeader.add_count = add_count;
    
    p = sizeof(struct DNS_HEADER);
    qname = (unsigned char*)(message + p);
    qnamelen = strlen((char*)qname)+1;
    DnsQueryData.DnsQuestion.qname = new unsigned char[qnamelen]; // '\0'
    strcpy((char*)DnsQueryData.DnsQuestion.qname, (char*)qname);
    ChangeNetToHostFormat(DnsQueryData.DnsQuestion.qname);
    p += strlen((char*)qname)+1;
    qinfo = (struct QUESTION*)(message + p);
    DnsQueryData.DnsQuestion.qtype = ntohs(qinfo->qtype);
    DnsQueryData.DnsQuestion.qclass = ntohs(qinfo->qclass);
    p += sizeof(struct QUESTION);

    //get dns answers.
    pread = (unsigned char*)(message + p);
    DnsQueryData.DnsAnswer = new struct DNS_RRS_DATA[ans_count];
    if (NULL == DnsQueryData.DnsAnswer) return -1;
    for (i=0; i<ans_count; i++){
        pread += GetDnsRRContent(pread, message, &DnsQueryData.DnsAnswer[i]);
    }
    
    //get dns authorities
    DnsQueryData.Authority = new struct DNS_RRS_DATA[auth_count];
    if (NULL == DnsQueryData.Authority) return -2;
    for (i=0; i<auth_count; i++){
        pread += GetDnsRRContent(pread, message, &DnsQueryData.Authority[i]);
    }

    //get dns additional
    DnsQueryData.Additional = new struct DNS_RRS_DATA[add_count];
    if (NULL == DnsQueryData.Additional) return -3;
    for (i=0; i<add_count; i++){
        pread += GetDnsRRContent(pread, message, &DnsQueryData.Additional[i]);
    }

    return 0;
}

unsigned int DnsQuery::ReadRRName(int flag, unsigned char* pread, const unsigned char* message, struct DNS_RRS_DATA* rrs_data)
{
    unsigned char *rname;
    unsigned char *p;
    unsigned jumped=0, offset;
    int i , j;
    int count = 0; //read bytes

    rname = new unsigned char[256];
    if (NULL == rname) return 0;
    
    rname[0] = '\0';

    p = pread;
    j = 0;
    //read the name int message buffer
    while(p!=NULL && *p != 0)
    {
        if(DNS_OFFSET_MASK == ((*p) & DNS_OFFSET_MASK))
        {
            offset = (((*p)&(~DNS_OFFSET_MASK))<<8)+*(p+1);
            p = (unsigned char*)(message + offset - 1); //the next loop,  p has + 1  ---!
            jumped = 1;  // jumped to another location so counting wont go up!
        }
        else 
            rname[j++]=*p;
        
        p++; // more attention ---!
        
        if(jumped == 0) count++; //if we havent jumped to another location then we can count up
    }
    if(jumped == 1) count++;  //number of steps we actually moved forward in the packet
    count++;         //move forward (skip the '\0' or the offset byte)
    rname[j]='\0';    //string complete

    ChangeNetToHostFormat(rname);

    if (DNS_GET_RR_NAME == flag)
        rrs_data->name = rname;
    else
        rrs_data->r_data = rname;
   
    return count;        
}


void DnsQuery::ReleaseRRContent(struct DNS_RRS_DATA* rrs_data)
{
    if (NULL == rrs_data) return;
    
    if (NULL != rrs_data->name) delete [] rrs_data->name;
    rrs_data->name = NULL;
    if (NULL != rrs_data->r_data) delete [] rrs_data->r_data;
    rrs_data->r_data = NULL;
}

void DnsQuery::ReleaseDnsQuery(void)
{
    int i;

    if (NULL != DnsQueryData.DnsAnswer){
        for (i=0;i<DnsQueryData.DnsHeader.ans_count;i++){
            ReleaseRRContent(&DnsQueryData.DnsAnswer[i]);
        }
        delete [] DnsQueryData.DnsAnswer;
        DnsQueryData.DnsAnswer = NULL;
        DnsQueryData.DnsHeader.ans_count = 0;
    }

    if (NULL != DnsQueryData.Authority) {
        for (i=0;i<DnsQueryData.DnsHeader.auth_count;i++){
            ReleaseRRContent(&DnsQueryData.Authority[i]);
        }
        delete [] DnsQueryData.Authority;
        DnsQueryData.Authority = NULL;
        DnsQueryData.DnsHeader.auth_count = 0;
    }

    if (NULL != DnsQueryData.Additional) {
        for (i=0;i<DnsQueryData.DnsHeader.add_count;i++){
            ReleaseRRContent(&DnsQueryData.Additional[i]);
        }
        delete [] DnsQueryData.Additional;
        DnsQueryData.Additional = NULL;;
        DnsQueryData.DnsHeader.auth_count = 0;
    }
    if (NULL != DnsQueryData.DnsQuestion.qname) 
        delete [] DnsQueryData.DnsQuestion.qname;
    DnsQueryData.DnsQuestion.qname = NULL;
    
}

void DnsQuery::EnableDnsQuery(void)
{
    DNS_DBG = 1;
}

void DnsQuery::DisableDnsQuery(void)
{
    DNS_DBG = 0;
}

