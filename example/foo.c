#include <stdio.h>
#include <stdlib.h>

double mymulfunc(double data){
    int i;
    double output = data;
    for(i=0; i<10; i++)
      output *=1.1;
    return output;
}
double myaddfunc(double data){
    int i;
    double output = data;
    for(i=0;i<10;i++)
      output +=1.1;
    return output;
}
int main(int argc, char * argv[]){
    double data = 1.0;
    data = mymulfunc(data);
    printf("fmul output : %.10f\n", data);
    data = myaddfunc(data);
    printf("fadd output : %.10f\n", data);
    return 0;
}
