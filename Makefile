all :
        gcc -o pcap-test pcap-test.c -lpcap

clean:
        rm -rf pcap-test
