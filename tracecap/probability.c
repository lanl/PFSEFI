#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "probability.h"
/* Global variables for dynamic probability */
struct probability_node* probability_list_head = NULL;
int current_probability_index = 0;

int proba_size(struct probability_node** head_ref){
  struct probability_node* current = *head_ref;
  struct probability_node* tmp= current;
  int count = 0;
  if (current == NULL)
	return 0;
  while(tmp!=NULL){
  	tmp=tmp->next;
	count++;
  }
  return count;
}
/* Given a reference (pointer to pointer) to the head
 *     of a list and an int, push a new node on the front
 *         of the list. */
void proba_push(struct probability_node** head_ref, double new_data)
{
    /* allocate node */
    struct probability_node* new_node =
            (struct probability_node*) malloc(sizeof(struct probability_node));
 
    /* put in the data  */
    new_node->data  = new_data;
   
    /* link the old list off the new node */
    new_node->next = (*head_ref);
   
    /* move the head to point to the new node */
    (*head_ref)    = new_node;
}

void proba_showall(struct probability_node** head_ref){
    struct probability_node* current = *head_ref;
    int count = 0; /* the index of the node we're currently
                  looking at */
    while (current != NULL)
    {
       printf("%lf ", current->data);
       count++;
       current = current->next;
    }
    printf("\n");


}
 
/* Takes head pointer of the linked list and index
 *     as arguments and return data at index*/
double proba_getNth(struct probability_node* head, int index)
{
    struct probability_node* current = head;
    int count = 0; /* the index of the node we're currently
                  looking at */
    int sz = proba_size(&head);
    index = sz-1-index;
    while (current != NULL)
    {
       if (count == index)
          return(current->data);
       count++;
       current = current->next;
    }
   
    /* if we get to this line, the caller was asking
 *        for a non-existent element so we assert fail */
    assert(0);              
}


/*   
 *
 *   Not used anymore
 *
 */
void proba_reverse(struct probability_node** head_ref){
    struct probability_node* current = *head_ref;
    if (current == NULL||current->next==NULL)
    	return;
    
    struct probability_node* temp = current->next;
    struct probability_node* temp_next;
    current->next = NULL;
    while(temp!=NULL){
	// save temp's next
	temp_next=temp->next;
	// redirect pointer
	temp->next = current;
	// update current and temp_next
	current = temp;
	temp = temp_next;
    }
    (*head_ref) = current;
}
 
void proba_init_list(char* file_name, probability_node** head_ref){
	FILE* fr;
	double val;
	char line[80];
	struct probability_node* current = *head_ref;
	// No need to reload the probability list
	if(current!=NULL)
	  return;
	// load the probability list
	fr = fopen(file_name, "rt");
	while(fgets(line, 80, fr)!=NULL)
	{
		val  = atof(line);
    		//printf("val:%lf\n", val);
		proba_push(&current, val);
	        //proba_showall(head_ref);
	}
	fclose(fr);
	(*head_ref) = current;
//	proba_reverse(&current);
}


//void proba_clean(probability_node** head_ref){
void proba_clean(){
	struct probability_node* current = probability_list_head;
        if(current == NULL){
 	  current_probability_index = 0;
	  return;
        }
	// More than one node in the list
	while(current != NULL){
		struct probability_node* tmp = current;
		current = tmp->next;
		free(tmp);
	}
	probability_list_head=NULL;
 	current_probability_index = 0;
}


