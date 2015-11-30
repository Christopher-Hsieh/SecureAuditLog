
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

void printlist( void );
void addMemBlock( char* );
void freeMem( void );

struct node {
   char* block;
   struct node *next;
};


struct node *head = (struct node *) NULL;

void addMemBlock( char *block )
{
   struct node *ptr;
   ptr = (struct node *) calloc( 1, sizeof(struct node ) );
   if( ptr == NULL )                   
       return;                           
   else {                                  
      ptr->block = block;
   }

  if( head == NULL )     
       head = ptr;               
   ptr->next = NULL;                  
}

void printlist() 
{
  struct node *ptr = head;
   while( ptr != NULL )           
   {
      printf("Block ->%s\n", ptr->block );          
      ptr = ptr->next;           
   }
}

void freeMem( )
{
  struct node *ptr = head;
  struct node *temp;

   if( head == NULL ) return;      

   head = NULL;

   while( ptr != NULL ) {  
      temp = ptr->next;     
      free(ptr->block);
      free(ptr);     
      ptr = temp;          
   }
}