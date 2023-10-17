#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>
#include <stdbool.h>

char* a = NULL;
int one = 0;
int have_list[9];
int (*puts_ptr)(const char*);
char *heap_list[9];
int heap_size[9];

void meau(){
    puts("1.add");
    puts("2.delete");
    puts("3.edit");
    puts("4.show");
    puts("5.exit");
    puts("please input your choice:");
}

void sub_4040(){
    if(have_list[7]==0){
        return;
    }
    else if(one==0){
        one=1;
        int size = 0x10;
        a = malloc(size);
        return;
    }
    else if(one == 1){
        one = 2;
        read(0,a,0x20); 
        puts_ptr = &puts;
        return;
    }
    else
    exit(0);
}

void banner(){
    setvbuf(stderr,0,2,0);
    setvbuf(stdout,0,2,0);
    setvbuf(stdin,0,2,0);
}

void add(){
    int index = 0;
    for(index = 0;have_list[index] != 0;index++);
    if(index >= 9){
        puts("full");
        return;
    }
    puts("size:");
    int size;
    scanf("%d",&size);
    if(size<=0 || size>=0x160){
        puts("no no no");
        exit(0);
    }
    heap_list[index]=malloc(size);
    puts("content:");
    read(0,heap_list[index],size);
    heap_size[index]=size;
    have_list[index]=1;
}

void delete(){
    puts("index:");
    int index;
    scanf("%d",&index);
    if(index<0 || index>=9){
        puts("no no no");
        return;
    }
    if(have_list[index]==1){
        free(heap_list[index]);
        heap_list[index]=NULL;
        have_list[index]=2;
        return;
    }
    puts("?");
}

void show(){
    puts("index:");
    int index;
    scanf("%d",&index);
    if(index < 0 || index >=9){
        puts("?");
        return;
    }
    if(have_list[index]==0 || have_list[index]==2){
        return;
    }
    write(1,heap_list[index],heap_size[index]);
    printf("\n");
}

void edit(){
    puts("index:");
    int index;
    scanf("%d",&index);
    if(index < 0 || index >=9){
        puts("?");
        return;
    }
    if(index < 7){
        return;
    } 
    if(have_list[index]==0 || have_list[index]==2){
        puts("?");
        return;
    }
    if(have_list[index]==1){
        puts("new content:");
        read(0,heap_list[index],heap_size[index]);
    }  
}

int main(){
    banner();

    while(1){
        meau();
        int choice;
        scanf("%d",&choice);
        if(choice==1)add();
        else if(choice==2)delete();
        else if(choice==3)edit();
        else if(choice==4)show();
        else if(choice==5)break;
        else if(choice==114514) sub_4040();
        else exit(0);
    }

    return 0;
}