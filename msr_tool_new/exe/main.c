
#include <sys/types.h>
#include <sys/stat.h>
#include<fcntl.h> 
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <string.h>
#define __USE_GNU     
#include <sched.h>   
#include <pthread.h>
#define SET_LEN 0x100
#define RDMSR   0x200
#define WRMSR   0x300
#define WCMD   0x400
#define IOW    0x600
#define IOR    0x700
#define CPUID    0x800
#define MEMW    0x900
#define MEMR    0xa00
#define DEVNAME  "/dev/simple"
#define BUFFER_SIZE 4096


int glen = 0;

struct scull_arg{
	int msr;
	int ecx;
	int ebx;
	int edx;
	int eax;
	int edi;
	int esi;
	int number;
        char * argv;
	uint16_t io_number;
	uint8_t data;
	unsigned long mem_address;
	unsigned long mem_data;

	
};



int dfd; //file handler for drvier
int edx=0;
int eax=0;
int eax_cpuid = 0;
int is_space(char c)
{
	if(c>='0' && c<= '9')
	  return 0;
	else if(c>='A' && c <='F')
	  return 0;
	else if(c>='a' && c <='f')
	  return 0;
	else
	  return 1;

}

char ati(char c)
{
	if(c>='0' && c<= '9')
	  return c-'0';
	else if(c>='A' && c <='F')
	  return c-'A' + 10;
	else if(c>='a' && c <='f')
	  return c-'a' + 10;

}
void  asctobin(char *src,char *des, int len)
{
	char l;
	char h;
	char *end;

	

	end = src + len;
	for(;src < end;){
		while(is_space(*src) && src <end)
			src++;
		if(src >=end)
		  break;
		h = ati(*src++);
		l = ati(*src++);

		*des ++ = (l & 0xf) |  ((h & 0xf) <<4);
		glen ++;
	}
}
void byte_oder(char *buf, int len)
{
	int i;
	char *p;
    	char *s, *e;
	char ch;

	for(i=0; i<len; i+=16)
	{
		s = buf + i;
		e = s+15;

		while(s<e){
			ch = *s;
			*s = *e;
			*e = ch;
			s++;
			e--;
		}
	}
}

void* thread_msr(void* arg)  
{  
    
    cpu_set_t mask,get;  
    int i = 0;   
    int flag = 0;  
    struct scull_arg *arg_para=(struct scull_arg *)arg;
    struct scull_arg arg_check;
    arg_check.msr=arg_para->msr;
    arg_check.number=arg_para->number;
    pthread_detach(pthread_self());  //prevent block
    CPU_ZERO(&mask);      
    CPU_SET(arg_para->number, &mask);  
    //printf("The %dst thread, mask is %d\n",arg_para->number,mask.__bits[0]);
    if(sched_setaffinity(0, sizeof(mask), &mask) == -1)      
    {  
        printf("set affinity failed..\n");  
	return 0;
    }  

        CPU_ZERO(&get);  
 	//printf("The %dst thread, mask is %d\n",arg_para->number,get.__bits[0]);
        if(sched_getaffinity(0, sizeof(get), &get) == -1)   
        {  
            printf("get failed..\n"); 
	    return 0; 
        }  
  	// printf("The %dst thread, mask is %d\n",arg_para->number,get.__bits[0]);
	while(!flag){        
	for(i = 0; i < arg_para->number+1; i++)  
        {  
            if(CPU_ISSET(i, &get))  
		{	
            	//	printf("thread_msr %d run on processor %d\n", getpid(), i);  
			
	   		flag=1;
			break;
		}
        }  
        }

     	if(!strcmp(arg_para->argv,"-cpuid"))
  	{	
		arg_para->eax = eax_cpuid;
		ioctl(dfd, CPUID,arg_para);
		printf("CPUID[%x] in CPU %d EAX is %x,EBX is %x,ECX is %x, EDX is %x\n",eax_cpuid,arg_para->number, arg_para->eax, arg_para->ebx,arg_para->ecx, arg_para->edx);
	}

	if(!strcmp(arg_para->argv,"-rdmsr"))
  	{	
		//int ret = 11;
		arg_para->edx=edx;
    		arg_para->eax=eax;
		//printf("MSR %x in CPU %d EAX is %x, EDX is %x\n",arg_para->msr, arg_para->number,arg_para->eax, arg_para->edx);
		ioctl(dfd,RDMSR, arg_para);
		//printf("Size is %d\n",sizeof(*arg_para));
		printf("MSR %x in CPU %d EAX is %x, EDX is %x\n",arg_para->msr, arg_para->number,arg_para->eax, arg_para->edx);

	}
	if(!strcmp(arg_para->argv,"-wrmsr"))
	{
		ioctl(dfd,WRMSR, arg_para);
	}
	if(!strcmp(arg_para->argv,"-rmwmsr"))
	{
		arg_check.edx=edx;
    		arg_check.eax=eax;
		ioctl(dfd,RDMSR, &arg_check);
		printf("Before Modified MSR %x in CPU %d EAX is %x, EDX is %x\n",arg_check.msr, arg_check.number,arg_check.eax, arg_check.edx);
		//printf("MSR %x in CPU %d EAX is %x, EDX is %x, ESI is %x, EDI is %x\n",arg_para->msr, arg_para->number,arg_para->eax, arg_para->edx, arg_para->esi, arg_para->edi);
		ioctl(dfd,WRMSR, arg_para);
		arg_check.edx=edx;
    		arg_check.eax=eax;
		ioctl(dfd,RDMSR, &arg_check);
		printf(" After Modified MSR %x in CPU %d EAX is %x, EDX is %x\n",arg_check.msr, arg_check.number,arg_check.eax, arg_check.edx);
		
	}
	pthread_exit(NULL);
} 
void* rmw_msr(void* arg)  
{  
    
    cpu_set_t mask,get;  
    int i = 0;    
    int flag = 0; 
    struct scull_arg *arg_para=(struct scull_arg *)arg;
    pthread_detach(pthread_self());  //prevent block
    arg_para->edx=edx;
    arg_para->eax=eax;
    CPU_ZERO(&mask);      
    CPU_SET(arg_para->number, &mask);  
    //printf("The %dst thread, mask is %d\n",arg_para->number,mask.__bits[0]);
    if(sched_setaffinity(0, sizeof(mask), &mask) == -1)      
    {  
        printf("set affinity failed..\n");  
	return 0;
    }  
  
        CPU_ZERO(&get);  
 	//printf("The %dst thread, mask is %d\n",arg_para->number,get.__bits[0]);
        if(sched_getaffinity(0, sizeof(get), &get) == -1)   
        {  
            printf("get failed..\n"); 
	    return 0; 
        }  
  	// printf("The %dst thread, mask is %d\n",arg_para->number,get.__bits[0]);
	while(!flag){
        for(i = 0; i < arg_para->number+1; i++)  
        {  
            if(CPU_ISSET(i, &get))  
		{	
            	//	printf("thread_msr %d run on processor %d\n", getpid(), i);  
			flag=1;
	   		break;
		}
        }  
       
        }
	
	ioctl(dfd,RDMSR,arg_para);
		

	pthread_exit(NULL);
}

static int read_type(int offset)  
{  
    void * map_base;  
    FILE *f;  
    int type,fd;  
  
#define     READ_REG32(reg)     ( *((volatile int *) (reg)) )  
#define     ALLOC_SIZE          (1024)  
   // printf("offset is %x\n",offset); 
    fd = open("/dev/mem", O_RDWR | O_SYNC);  
    if (fd) {  
    //    printf("Success to open /dev/mem fd=%08x\n", fd);  
    }  
    else {  
        printf("Fail to open /dev/mem fd=%08x\n", fd);    
    }  
    //map_base = mmap(0, ALLOC_SIZE, PROT_READ, MAP_PRIVATE, fd, 0x35004000);  
   // printf("map_offset is %x\n",(offset&0xfffff000));
    map_base = mmap(0, ALLOC_SIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, (offset & 0xfffff000));
  // printf("map_base is %x\n",map_base);
    type = READ_REG32(map_base + (offset & 0xfff));  
  
    close(fd);  
    munmap(map_base, ALLOC_SIZE);  
  
    printf("Mem_address[%08x-%08x] = value[%08x] \n", offset,offset+0x4, type);  
  
   // type = (type & ( 1 << 27 )) >> 27 ;  
  
  //  printf("reg32[%08x] = value[%08x] \n", map_base, type);  
  
   return type;  
}

static void dump_mem(struct scull_arg *arg, int dump_size, unsigned char* file_name){

	FILE * file_dump;
	unsigned long data;
	int dump_size_all;
	int i = 0;
	//printf("size is %d\n",sizeof(data));
	dump_size_all = dump_size * 1024 * 1024; //# 1M is the min size
	//dump_size_all = dump_size*16; //# 1M is the min size
	file_dump = fopen(file_name, "wb");
	for(i = 0; i < dump_size_all; i=i+8 ){
	ioctl(dfd, MEMR, arg);
	data = arg->mem_data;
//	printf("mem add is 0x%016llx,data is 0x%016llx\n",arg->mem_address,data);
	fwrite(&data,8,1,file_dump);
	arg->mem_address = 8 + arg->mem_address; 
	}
	fclose(file_dump);
	return;

}
static int write_type(int offset,uint8_t data)  
{  
    void * map_base;  
    FILE *f;  
    int type,fd;  
  
#define     READ_REG32(reg)     ( *((volatile int *) (reg)) )  
#define     ALLOC_SIZE          (1024)  
  //	printf("%x\n",data);
    fd = open("/dev/mem", O_RDWR | O_SYNC);  
    if (fd) {  
    //    printf("Success to open /dev/mem fd=%08x\n", fd);  
    }  
    else {  
        printf("Fail to open /dev/mem fd=%08x\n", fd);    
    }  
    //map_base = mmap(0, ALLOC_SIZE, PROT_READ, MAP_PRIVATE, fd, 0x35004000);  
    map_base = mmap(0, ALLOC_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, fd, (offset & 0xfffff000));
   // type = READ_REG32(map_base + (offset & 0xfff));  
     memcpy((map_base + (offset & 0xfff)),&data,1);
    close(fd);  
    munmap(map_base, ALLOC_SIZE);   
  
   // printf("Mem_address[%08x-%08x] = value[%08x] \n", offset,offset+0x4, type);  
  
   // type = (type & ( 1 << 27 )) >> 27 ;  
  
  //  printf("reg32[%08x] = value[%08x] \n", map_base, type);  
  
   // return type;  
}

int main(int argc, char **argv)
{
	int sfd;
	int num_s=0;
	int flag_core=0;
	int filesize;
	char * buf;
	int ret = 1;
	struct scull_arg  arg;
	char *tempbuf;
	char *filebuf;
	int num = sysconf(_SC_NPROCESSORS_CONF);  // get the total cpu number of this system 
    	int created_thread = 0;  
    	int myid;    
    	pthread_t ptid = 0; 
	pthread_t ptid1 = 0; 
        int i=0;
	int p =0;
	int mem_address;
	int dump_size;
	unsigned char file_name[100];
    	cpu_set_t mask;  
 	uint8_t mem_data=0;
	
	dfd = open(DEVNAME,O_RDWR);
	
//	FILE * file_dump;
//	unsigned long data;
	//unsigned long data1 = 0;
	//printf("data addr is %llx\n",&data);
	//printf("data1 addr is %llx\n",&data1);
//	int dump_size_all;
	//int i = 0;
//	int * a;
//	int b = 1;
//	a = &b;
//	char * c;
//	char d = 'a';
//	c = &d;
//	printf("size is %d\n",sizeof(data));
//	printf("a = %d\n",a);
//	printf("c = %s\n",c);
	if(dfd < 0){
		printf("driver is no load\n");
		return -1;
	}
        if(argc==1){
		printf("******************************************************** Manual ************************************************\n");
		printf("-p patch_file										: update ucode\n");
		printf("-rdmsr msrnumber -core [cpunumber] -edx [edx] -eax [eax] -edi [edi] -esi [esi]	 	: read msr\n");
		printf("-wrmsr msrnumber high32 low32 -core [cpunumber] -edi [edi] -esi [esi]			: write msr, value is [edx:eax]\n");
		printf("-rmwmsr msrnumber SXX/RXX -core [cpunumber] -edx [edx] -eax [eax] -edi [edi] -esi[esi]	: SXX to set a bit, Rxx to reset a bit\n");
		printf("-ior io_address 	: Read IO, data size is 1 byte\n");
		printf("-iow io_address data	: Write IO, data size is 1 byte \n");
		printf("-memr mem_address 	: Read Physical Memory(/dev/mem,only below 1MB), data size is 4 byte  \n");
		printf("-memread mem_address 	: Read Physical Memory(driver)\n");
		printf("-memdump mem_address dump_size filename							: Dump Physical Memory, size unit is M \n");
		printf("-memw mem_address data	: Write Physical Memory, data size is 1 byte \n");
                printf("-cpuid eax		: Execute Cpuid[eax] instruction \n");
		printf(" Notice: For most of MSRs, parameters in \"[]\" are not essential\n");
		printf("*****************************************************************************************************************\n");
		return 0;

	}
	else{
        arg.argv=argv[1];
		arg.edx=0;
		arg.eax=0;
		arg.edi=0;
		arg.esi=0;
		arg.io_number=0;
		arg.data=0;
        arg.ecx=0;
        arg.ebx=0;
        arg.mem_address = 0;
        arg.mem_data = 0; // the data struct to driver must give a value, if not system will give a random value, it may crash the driver
    	//printf("arg.mem_data addr is %llx\n",&arg.mem_data);
    	//printf("arg.mem_address addr is %llx\n",&arg.mem_address);
		if(!strcmp(argv[1],"-cpuid")){

			if(argc<3)
			{
				printf("Please input EAX value \n");
				return 0;
			}
			sscanf(argv[2],"%x",&arg.eax);
			eax_cpuid = arg.eax;
			p=3;
			argc=argc-3;
			while(argv[p])
			{
				if(!argc) break;
				if(!strcmp(argv[p],"-core"))
				{
					
					if(!argv[p+1]){
						printf("Please input CPU number\n");
						return 0;					
					}
					sscanf(argv[p+1],"%d",&num_s);
					flag_core=1;
					p=p+2;
					continue;
			
				}
			}
			if(flag_core ==1)
				num=num_s+1;		
			//printf("cpu number is %d\n",num);
			for(i = num_s; i < num; i++)  
        		{  
                	arg.number=i;
                      
             		ret = pthread_create(&ptid, NULL, thread_msr, &arg);
 			if(ret)  
     			{  
				printf("Create thread failed\n");
        			return -1;  
    			}  
		
			pthread_join(ptid,NULL);
        		}
			
	        	return 0;
			
		}
		if(!strcmp(argv[1],"-memr")){

			if(argc<3)
			{
				printf("Please input Mem address \n");
				return 0;
			}
			sscanf(argv[2],"%x",&mem_address);
			printf("mem_addr is %x\n",mem_address);
			read_type(mem_address);
			
			return 0;
		}
		if(!strcmp(argv[1],"-memdump")){
			
			if(argc<5)
		{		

			printf("Please input the mem address, dump size and file name!\n");
			return 0;
		}
			sscanf(argv[2],"%llx",&arg.mem_address);
			sscanf(argv[3],"%x",&dump_size);
			sscanf(argv[4],"%s",&file_name);
			printf("Dump mem file name is %s\n",file_name);
			dump_mem(&arg,dump_size,file_name);
			return 0;	
		}
		if(!strcmp(argv[1],"-memw")){

			if(argc<4)
			{
				printf("Please input Mem address and data\n");
				return 0;
			}
			sscanf(argv[2],"%x",&mem_address);
			sscanf(argv[3],"%x",&mem_data);
			write_type(mem_address,mem_data);
			
			return 0;
		}
		if(!strcmp(argv[1],"-memread")){

                        if(argc<3)
                        {
                                printf("Please input Mem address \n");
                                return 0;
                        }
                       // sscanf(argv[2],"%x",&mem_address);
                       // printf("mem_addr is %x\n",mem_address);
			sscanf(argv[2],"%llx",&arg.mem_address);
			ioctl(dfd, MEMR, &arg);
			printf("Mem address 0x%016llx is 0x%016llx\n",arg.mem_address,arg.mem_data);
                        return 0;

                }
		if(!strcmp(argv[1],"-iow")){

			if(argc<4)
			{
				printf("Please input IO number and data\n");
				return 0;
			}
			sscanf(argv[2],"%x",&arg.io_number);
			sscanf(argv[3],"%x",&arg.data);
			ioctl(dfd, IOW,&arg);
			return 0;
		}
		if(!strcmp(argv[1],"-ior")){

			if(argc<3)
			{
				printf("Please input IO number\n");
				return 0;
			}
			sscanf(argv[2],"%x",&arg.io_number);
		
			ioctl(dfd, IOR,&arg);
			printf("IO number %x is %x\n",arg.io_number,arg.data);
			return 0;
		}
		//printf("command is %s\n",arg.argv);
		if(!strcmp(argv[1],"-rdmsr")){
			if(argc<3)
			{
				printf("Please input MSR number\n");
				return 0;
			}
			
			sscanf(argv[2],"%x",&arg.msr);
			
			p=3;
			argc=argc-3;
			while(argv[p])
			{
				if(!argc) break;
				if(!strcmp(argv[p],"-core"))
				{
					
					if(!argv[p+1]){
						printf("Please input CPU number\n");
						return 0;					
					}
					sscanf(argv[p+1],"%d",&num_s);
					flag_core=1;
					p=p+2;
					continue;
			
				}
				if(!strcmp(argv[p],"-edx"))
				{
					
					if(!argv[p+1]){
						printf("Please input EDX\n");
						return 0;					
					}
					sscanf(argv[p+1],"%x",&arg.edx);
					edx=arg.edx;
					p=p+2;
					continue;
			
				}
				if(!strcmp(argv[p],"-eax"))
				{
					
					if(!argv[p+1]){
						printf("Please input EAX\n");
						return 0;					
					}
					sscanf(argv[p+1],"%x",&arg.eax);
					eax=arg.eax;
					p=p+2;
					continue;
			
				}
				if(!strcmp(argv[p],"-edi"))
				{
					
					if(!argv[p+1]){
						printf("Please input EDI\n");
						return 0;					
					}
					sscanf(argv[p+1],"%x",&arg.edi);
					p=p+2;
					continue;
			
				}
				if(!strcmp(argv[p],"-esi"))
				{
					
					if(!argv[p+1]){
						printf("Please input ESI\n");
						return 0;					
					}
					sscanf(argv[p+1],"%x",&arg.esi);
					p=p+2;
					continue;
			
				}
				argc=argc-1;
			}
			
			//printf("Core is %d, EDX=%x, EAX=%x,EDI=%x,ESI=%x\n",num_s, arg.edx, arg.eax, arg.edi, arg.esi);
			if(flag_core ==1)
				num=num_s+1;		
			//printf("cpu number is %d\n",num);
			for(i = num_s; i < num; i++)  
        		{  
                	arg.number=i;
                      
             		ret = pthread_create(&ptid, NULL, thread_msr, &arg);
 			if(ret)  
     			{  
				printf("Create thread failed\n");
        			return -1;  
    			}  
		
			pthread_join(ptid,NULL);
        		}
			
	        	return 0;
		}	
		if(!strcmp(argv[1],"-wrmsr")){


			if(argc<5)
			{
				printf("Please input MSR number and data\n");
				return 0;
			}
			sscanf(argv[2],"%x",&arg.msr);
			sscanf(argv[3],"%x",&arg.edx);
			sscanf(argv[4],"%x",&arg.eax);
			
		//printf("MSR %x EAX is %x, EDX is %x\n",arg.msr, arg.eax, arg.edx);
			p=5;
			argc=argc-5;
			while(argv[p])
			{
				if(!argc) break;
				if(!strcmp(argv[p],"-core"))
				{
					
					if(!argv[p+1]){
						printf("Please input CPU number\n");
						return 0;					
					}
					sscanf(argv[p+1],"%d",&num_s);
					flag_core=1;
					p=p+2;
					continue;
			
				}
				if(!strcmp(argv[p],"-edi"))
				{
					
					if(!argv[p+1]){
						printf("Please input EDI\n");
						return 0;					
					}
					sscanf(argv[p+1],"%x",&arg.edi);
					p=p+2;
					continue;
			
				}
				if(!strcmp(argv[p],"-esi"))
				{
					
					if(!argv[p+1]){
						printf("Please input ESI\n");
						return 0;					
					}
					sscanf(argv[p+1],"%x",&arg.esi);
					p=p+2;
					continue;
			
				}
				argc=argc-1;
			}
			//printf("Core is %d, EDX=%x, EAX=%x,EDI=%x,ESI=%x\n",num_s, arg.edx, arg.eax, arg.edi, arg.esi);
			

			if(flag_core ==1)
				num=num_s+1;		
			//printf("cpu number is %d\n",num);
			for(i = num_s; i < num; i++)  
        		{  
                	arg.number=i;
                      
             		ret = pthread_create(&ptid, NULL, thread_msr, &arg);
 			if(ret)  
     			{  
				printf("Create thread failed\n");
        			return -1;  
    			}  
		
			pthread_join(ptid,NULL);
        		}
	        	return 0;
	
		}
        	if(!strcmp(argv[1],"-rmwmsr")){

			if(argc<4)
			{
				printf("Please input MSR number and modified bits\n");
				return 0;
			}
                	int number=0;
                        int k=0;
                	char flag='\0';
			char * input;
          		char * bit;
			sscanf(argv[2],"%x",&arg.msr);
	      		p=4;
			argc=argc-4;
			while(argv[p])
			{

				if(!argc) break;
				if(!strcmp(argv[p],"-core"))
				{
					
					if(!argv[p+1]){
						printf("Please input CPU number\n");
						return 0;					
					}
					sscanf(argv[p+1],"%d",&num_s);
					flag_core=1;
					p=p+2;
					continue;
			
				}
				if(!strcmp(argv[p],"-edx"))
				{
					
					if(!argv[p+1]){
						printf("Please input EAX\n");
						return 0;					
					}
					sscanf(argv[p+1],"%x",&arg.edx);
					edx=arg.edx;
					p=p+2;
					continue;
			
				}
				if(!strcmp(argv[p],"-eax"))
				{
					
					if(!argv[p+1]){
						printf("Please input EAX\n");
						return 0;					
					}
					sscanf(argv[p+1],"%x",&arg.eax);
					eax=arg.eax;
					p=p+2;
					continue;
			
				}
				if(!strcmp(argv[p],"-edi"))
				{
					
					if(!argv[p+1]){
						printf("Please input EDI\n");
						return 0;					
					}
					sscanf(argv[p+1],"%x",&arg.edi);
					p=p+2;
					continue;
			
				}
				if(!strcmp(argv[p],"-esi"))
				{
					
					if(!argv[p+1]){
						printf("Please input ESI\n");
						return 0;					
					}
					sscanf(argv[p+1],"%x",&arg.esi);
					p=p+2;
					continue;
			
				}
				argc=argc-1;
			}
			if(flag_core ==1)
				num=num_s+1;		
			//printf("cpu number is %d,%d\n",num,num_s);
			for(i = num_s; i < num; i++)  
        		{  
                	arg.number=i;
                      	k=0;
             		ret = pthread_create(&ptid, NULL, rmw_msr, &arg);
 			if(ret)  
     			{  
				printf("Create thread failed\n");
        			return -1;  
    			}  
		
			pthread_join(ptid,NULL);
        		
			
			//printf("MSR %x EAX is %x, EDX is %x rmwmsr\n",arg.msr, arg.eax, arg.edx);
			//printf("%c,%c,%c,%c,%c,%c\n",argv[3][0],argv[3][1],argv[3][2],argv[3][3],argv[3][4],argv[3][5]);
			while(argv[3][k]){
				
				flag=argv[3][k];
				//printf("flag is %c\n",flag);
				input=&argv[3][k+1];
				sscanf(input,"%d",&number);
				//printf("flag is %c, bit is %d\n",flag,number);
				if(number >= 10 && number <= 63 ){
				k=k+3;
			
				}
				else{
					if(number >= 0 && number < 10 ){
					k=k+2;		
					}
					else{
						printf("Input bit number is aalid\n");
						return 0;
					}	
				}
				if(flag=='s'|flag=='S'){
					if(number>=0 && number <=31)
					{arg.eax=arg.eax | (1<<number);}
					else{
						if(number>=32 && number <=63)
						{arg.edx=arg.edx | (1<<(number-32));}
					}
				}
				else{
					if(flag=='r'|flag=='R'){
						if(number>=0 && number <=31)
						{arg.eax=arg.eax & (~(1<<number));}
				
						else{
							if(number>=32 && number <=63)
							{arg.edx=arg.edx & (~(1<<(number-32)));}
						}
                 
					}
         				else{
						printf("Modified command is invalid\n");
						return 0;
					}	
				}
                
			}
			
			//printf("MSR %x EAX is %x, EDX is %x rmwmsr\n",arg.msr, arg.eax, arg.edx);
			ret = pthread_create(&ptid, NULL, thread_msr, &arg);
 			if(ret)  
     			{  
				printf("Create thread failed\n");
        			return -1;  
    			}  
		
			pthread_join(ptid,NULL);
			}
	        	return 0;
	
	
		}
		if(!strcmp(argv[1],"-p")){
			if(argc <3){
				printf("please use patch file\n");
				return -1;
			}
  
    			sfd = open(argv[2], O_RDONLY);  
    			if(sfd == NULL){
				printf("no such file\n");
        			return -1;  
			}
    			filesize = lseek(sfd, 0, SEEK_END);  
			printf("%s, size is %d\n", argv[2],filesize);
    			lseek(sfd,0,SEEK_SET);
	
		
		//set file len and mmap
			arg.msr = filesize;
			ioctl(dfd,SET_LEN ,&arg);

			filebuf = tempbuf = malloc(filesize);
	
			buf = mmap(NULL, filesize , PROT_READ|PROT_WRITE, MAP_SHARED , dfd , 0); 
	
		//read file to memory
			while(ret){
	
				ret= read(sfd, tempbuf, BUFFER_SIZE); //ret is the length returned, 0 for EOF, <0 if error
			//printf("red %d byte \n", ret); 
				if(ret < 0){
					printf("read Error ret is %d\n", ret); 
            				exit(1);
				}
				tempbuf += ret;
		
			}

			asctobin(filebuf, buf, filesize);
    			byte_oder(buf, glen);

			arg.msr = 0x79;
			ioctl(dfd, WRMSR,&arg);
	
			arg.msr = 0x1205;
			ioctl(dfd,RDMSR, &arg);
			printf("MSR %x EAX is %x, EDX is %x\n",arg.msr, arg.eax, arg.edx);

			arg.msr = 0x1208;
			ioctl(dfd, WCMD,&arg);

			arg.msr = 0x1208;
			ioctl(dfd,RDMSR, &arg);
			printf("MSR %x EAX is %x, EDX is %x\n",arg.msr, arg.eax, arg.edx);
			
			munmap(buf, filesize);

			close(dfd);
    			close(sfd);  
			free(filebuf);
			return 0;
		}
		else
		{	
			printf("Invalid Command\n");
			return 0;
			}
		
	}
	
	close(dfd);
	return 0;
}

