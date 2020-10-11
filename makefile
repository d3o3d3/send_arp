LDLIBS=-lpcap
CXXFLAGS=-std=c++11

all: send-arp

send-arp: main.o arphdr.o ethhdr.o ip.o mac.o getmy.o attack.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f send-arp *.o
