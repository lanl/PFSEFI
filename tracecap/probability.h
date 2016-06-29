

/* Link list node */
typedef struct probability_node
{
    double data;
    struct probability_node* next;
}probability_node;
 

void proba_push(struct probability_node** head_ref, double new_data);
double proba_getNth(struct probability_node* head, int index);
void proba_reverse(struct probability_node** head_ref);
void proba_init_list(char* file_name, probability_node** head_ref);
int proba_size(struct probability_node** head_ref);
void proba_showall(struct probability_node** head_ref);
extern void proba_clean();

extern struct probability_node* probability_list_head;
extern int current_probability_index;



