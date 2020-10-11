#include "mac.h"
#include "getmy.h"
#include <arpa/inet.h>



int getmac (char * interface, uint8_t * ad)
{
  struct ifreq s;

  int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

  strcpy(s.ifr_name, interface);
  if( 0 == ioctl(fd, SIOCGIFHWADDR, &s)){
      memcpy(ad, s.ifr_addr.sa_data, Mac::SIZE);
      return 0;
  }
  return 1; 
}

int getip(char * interface, char * ip)
{
  struct ifreq s;

  int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

  strcpy(s.ifr_name, interface); 
  if( 0 == ioctl(fd, SIOCGIFADDR, &s)){
      // printf("%s\n", inet_ntoa(((struct sockaddr_in *)&s.ifr_addr)->sin_addr));
      // memcpy(ip, &(((struct sockaddr_in *)&s.ifr_addr)->sin_addr.s_addr), 4);
      // (*ip) = ((struct sockaddr_in *)&s.ifr_addr)->sin_addr.s_addr;
      // ip = inet_ntoa(((struct sockaddr_in *)&s.ifr_addr)->sin_addr);
      inet_ntop(AF_INET, &((struct sockaddr_in *)&s.ifr_addr)->sin_addr, ip, 16);
      return 0;
  }
  return 1;
}