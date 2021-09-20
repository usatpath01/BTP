#include <stdio.h>
#include <stdlib.h>
void execution_unit1(FILE *fptr)
{
	FILE *newfptr;
	for(int i=1;i<5;i++)
	{
		
		fprintf(fptr, "doing first open system call %d\n",1);
		newfptr = fopen("lol.txt", "w+");
		fprintf(fptr,"done first open system call %d\n",1);
		fprintf(fptr,"doing first some calculation %d\n",1);
		fprintf(fptr, "doing first close system call %d\n",1);
		fclose(newfptr);
		fprintf(fptr,"done first close system call %d\n",1);
	}

	fprintf(fptr,"completed loop");
}

void execution_unit2(FILE *fptr)
{
	FILE *newfptr;
	for(int i=1;i<5;i++)
	{
		newfptr = fopen("lol.txt", "w+");
		fprintf(fptr,"done second open system call2 %d\n",2);
		fprintf(fptr,"doing second some calculation2 %d\n",2);
		fprintf(fptr,"doing second close system call2 %d\n",2);
		fclose(newfptr);
		fprintf(fptr,"done second close system call2 %d\n",2);
	}

	fprintf(fptr,"completed loop2");
}

void execution_unit3(FILE *fptr)
{
	FILE *newfptr;
	for(int i=1;i<5;i++)
	{
		fprintf(fptr,"doing third open system call %d\n",3);
		newfptr = fopen("lol.txt", "w+");
		fprintf(fptr,"done third open system call3 %d\n",3);
		fprintf(fptr,"doing third some calculation3 %d\n",3);
		fprintf(fptr,"doing third close system call3 %d\n",3);
		fclose(newfptr);
	}

	fprintf(fptr,"completed loop3");
}


int main()
{
	int x;
	scanf("%d",&x);
	FILE *fptr = fopen("/var/log/testing/access.txt", "w+");


	if(!fptr)
	{	
		printf("error\n");
		return 0;
	}

	if(x==1)
		execution_unit1(fptr);
	if(x==2)
		execution_unit2(fptr);
	if(x==3)
		execution_unit3(fptr);
}