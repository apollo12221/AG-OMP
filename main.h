/* struct types to define variables to store the entries from the input .nm and .xp */

#define maxStrSize 20

typedef struct {
  char id[maxStrSize];
  char name[maxStrSize];
} assetStruct;

typedef struct {
  char asset_id[maxStrSize];
  char property[maxStrSize];
  char op[maxStrSize];
  char value[maxStrSize];
} qualityStruct;

typedef struct {
  char asset_from_id[maxStrSize];
  char asset_to_id[maxStrSize];
  char direction[maxStrSize];
  char property[maxStrSize];
  char op[maxStrSize];
  char value[maxStrSize];
} topologyStruct;

typedef struct {
 char id[maxStrSize];
 char name[maxStrSize];
 char params[maxStrSize];
} exploitStruct;

typedef struct {
 char id[maxStrSize];
 char exploit_id[maxStrSize];
 char type[maxStrSize];
 char param1[maxStrSize];
 char param2[maxStrSize];
 char property[maxStrSize];
 char value[maxStrSize];
 char op[maxStrSize];
 char dir[maxStrSize];
} exploit_preconditionStruct;

typedef struct {
 char id[maxStrSize];
 char exploit_id[maxStrSize];
 char type[maxStrSize];
 char param1[maxStrSize];
 char param2[maxStrSize];
 char property[maxStrSize];
 char value[maxStrSize];
 char op[maxStrSize];
 char dir[maxStrSize];
 char action[maxStrSize];
} exploit_postconditionStruct;

typedef struct{
    unsigned int hValue;
    int seqNum;
    int unitState;
} hashItem;













