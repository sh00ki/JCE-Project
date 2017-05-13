#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "slist.h"

// Yoad Shiran - 302978713

void slist_init(slist_t *pointer_list)
{
	slist_head(pointer_list)=NULL;
	slist_tail(pointer_list)=NULL;
	slist_size(pointer_list)=0;
}
void slist_destroy(slist_t *list_p ,slist_destroy_t flag)
{
	if (list_p==NULL)
	{
		return;
	}
	slist_node_t *temp_p;
	temp_p = slist_head(list_p);
	while(temp_p!= NULL)
	{
		slist_head(list_p) = slist_next(temp_p);
		if (flag==SLIST_FREE_DATA)
		{
			free(slist_data(temp_p));
		}
		free(temp_p);
		temp_p = slist_head(list_p);
	}
	free(temp_p);
	slist_size(list_p) = 0;
return;
}

void *slist_pop_first(slist_t *list)
{
	if (slist_head(list)==NULL)
	{
		return NULL;
	}
	slist_node_t *temp_p=NULL;
	void *PopValue;
	temp_p = slist_head(list);
	PopValue= slist_data(temp_p);
	slist_head(list) =slist_next(temp_p);
	free(temp_p);
	int countSize = slist_size(list) -1; 
	if (countSize==0) // if the list have one node
	{
		slist_tail(list)=NULL;
		slist_head(list)=NULL;
		slist_size(list)=0;
	}
	return(PopValue); // return the Value of head list
	
}

int slist_append(slist_t *list,void *Value)
{
	slist_node_t *temp_p=NULL;
	if (Value == NULL)
	{ // if no have Value
		return 0;
	}
	temp_p=(slist_node_t *)calloc(1,sizeof(slist_node_t));
	if(temp_p==NULL)
	{
		return -1;
	}
	slist_data(temp_p) = Value;
	slist_next(temp_p)=NULL;
	if (slist_head(list)==NULL)
	{
		slist_head(list) = temp_p;
		slist_tail(list) = temp_p;
		slist_size(list)++;
		return 0;
	}
	slist_next(slist_tail(list)) = temp_p;
	slist_tail(list) = temp_p;

	slist_size(list)++;
	return 0;

}
int slist_prepend(slist_t *list,void *Value)
{
	if (Value == NULL)
	{ // if no have Value
		return 0;
	}
	slist_node_t *temp_p;
	temp_p=(slist_node_t *)calloc(1,sizeof(slist_node_t));
	if(temp_p==NULL)
	{
		return -1;
	}
	slist_data(temp_p)=Value;
	temp_p->next = NULL;
	if (slist_head(list)==NULL) // the list is empty
	{
		slist_head(list) = temp_p;
		slist_tail(list) = temp_p;
		slist_next(temp_p) = NULL;
		slist_size(list) = 1;
		return 0;
	}
	slist_next(temp_p) = slist_head(list);
	slist_head(list) = temp_p;
	if (slist_tail(list)==NULL)
	{
		slist_tail(list)=temp_p;
	}
	slist_size(list)++;
	return 0;
}

int slist_append_list(slist_t* listOne, slist_t* listSec) {
	if (slist_tail(listSec) == NULL && slist_head(listOne) == NULL)
	{ // both of list is NULL
		return 0;
	}
	if (slist_head(listSec) == NULL)
	{ // list two is NULL
		return 0;
	}
	if(!listOne || !listSec) {return -1;}
	if(slist_size(listSec) == 0) {return 0;}
	slist_node_t* p = slist_head(listSec);
	while(p) {
		if( slist_append(listOne, p->data) == -1 ) {return -1;}
		p = slist_next(p);
	}
	slist_size(listOne) += slist_size(listSec);
/*	slist_destroy(l2, SLIST_LEAVE_DATA);*/
	return 0;
	
}