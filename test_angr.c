#include<stdio.h>

int main()
{
	int n;
	scanf("%d",&n);
	for(int i=0;i<n;i++)
	{
		if(i%2==0)
			printf("even\n");
		else
			printf("odd\n");
	}
	return 0;
}