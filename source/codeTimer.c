#include "../hedder/global_param.h"
static struct timeval before, after;  

void TimerOn(){
	gettimeofday(&before,NULL);
}

unsigned int TimerOff()
{
    gettimeofday(&after,NULL);
	return (1000000*(after.tv_sec-before.tv_sec) + (after.tv_usec-before.tv_usec)/1);
}