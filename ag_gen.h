/*struct types to define an attack graph instance and its components*/

typedef struct {
    int asset_name;     
    int num_Q;
} digitAsset;

typedef struct {
    short asset_id;
    short property;
    char op;
    short value;
    float fvalue; 
} digitQuality;

typedef struct {
    char param1;
    short property;     
    char op;
    short value;
    char type;
    float fvalue;
} digitPrecondQuality;

typedef struct {
    char param1;
    short property;
    char op;
    short value;
    char action;
    float fvalue;
} digitPostcondQuality;

typedef struct {
    short from_asset_id;
    short to_asset_id;
    short property;
    char dir;
} digitTopology;

typedef struct {
    char param1;
    char param2;
    short property;
    char dir;
} digitPrecondTopology;

typedef struct {
    char param1;
    char param2;
    short property;
    char dir;
    char action;
} digitPostcondTopology;

typedef struct {
    int id;
    int name;
    int num_params;
    int num_preQ;
    int num_preT;
    int num_postQ;
    int num_postT;
    digitPrecondQuality preQ[10];
    digitPrecondTopology preT[10]; 
    digitPostcondQuality postQ[10];
    digitPostcondTopology postT[10]; 
} digitExploit;

typedef struct {
    int numOfQualities;
    digitQuality hypothetical_qualities[5];
    int numOfTopologies;
    digitTopology hypothetical_topologies[5];
    int numOfParams;
    int perm[5];
} digitAssetGroup;

//define a node in the attack graph
typedef struct {
    int id;
    short numOfQualities;
    digitQuality qualities[80];
    short numOfTopologies;
    digitTopology topologies[120];
} digitFactbase;

//define an edge in the attack graph
typedef struct {
    int id;
    int from_node;
    int to_node;
    int exploit_id;
} digitEdge;

typedef struct{
    int numOfAssets;
    digitAsset assets[120];
    int numOfInitQualities;
    digitQuality initial_qualities[80];
    int numOfInitTopologies;
    digitTopology initial_topologies[120];
    int numOfExploits;
    digitExploit exploits[100];
    unsigned int numOfFactbases;
    digitFactbase factbases[3200000];
    unsigned long factbase_hashes[3200000];
    unsigned int numOfEdges;
    digitEdge edges[30000000];
    int workloads[10000];
} AGGenDigitInstance;

typedef struct{
    unsigned long hashNum;
    int factbaseID;
} hashUnit;

extern int numThreads;
extern int initQSize;
