#include "dnsquery.h"


#define TRYTIMES 3
int main(int argc, char *argv[])
{
    DnsQuery dnsquery;
    int ret;
    int i;
    int j;
    int start = 1;
    
    if (argc < 2 || 0 == strcmp("-h",argv[1])) {
        cout << "Command:"<<endl;
        cout << " dnsquery [-vh] hostname nameserver1 nameserver2 nameserver3 ..."<<endl;
        cout << " i.e.: \"dnsquery www.sina.com 221.12.33.227\""<<endl;
        system("PAUSE");
        return -1;
    }
    cout<< "Solve the hostname: "<<argv[start]<<", with nameserver:";
    for (i = 2; i<argc;i++)
        cout<<" "<<argv[i];
    cout<<endl;

    if (0 == strcmp("-v",argv[1])) {
        start++;
        dnsquery.EnableDnsQuery();
    }
    
    while (1)
    {
        for (i=start+1; i<argc; i++){
            j = 0;
            cout<< "Solving the hostname: "<<argv[start]<<", with nameserver:"<<argv[i]<<"...";
            while (j < TRYTIMES){
                ret = dnsquery.GetHostByNameWithNS(argv[start], argv[i]);
                if (ret < 0){ 
                    j++;
                    dnsquery.ReleaseDnsQuery();
                    Sleep(5000); 
                }
                else
                    break;
            }
            if (j >= TRYTIMES) {
                cout << "FAILED!!!!!!"<<endl;
                Beep(2550,1200);
            }
            else  {
                if (start > 1)
                    dnsquery.PrintDnsResult();
                else
                    cout << "OK"<<endl;
                dnsquery.ReleaseDnsQuery();
            }
            
        }
        Sleep(5000);
    }
    
    return 0;
}
