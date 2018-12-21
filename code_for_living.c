#include <stdio.h>
int main(){
	int a = 3;
	int b = 5;
	int c;
    scanf("give a value for c: %d \n", &c);
    int d;

    d = a +b +c;

    if (d <=10){
      printf("c less than a\n");
    } else if (d==11){
    	printf("c is equal to a\n");
    }else{
    	printf("c is greater than a\n");
    }

    printf("Alles klar \n");

}