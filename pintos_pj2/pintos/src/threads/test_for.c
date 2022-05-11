
#include "interrupt.h"

int main() {

	//struct intr_frame if;
	printf("%d\n", sizeof(struct intr_frame));
	printf("%d\n", sizeof(void));
	printf("%d\n: void*", sizeof(void*));
	//printf("%d\n", sizeof(if.*esp));

return 0;
}
