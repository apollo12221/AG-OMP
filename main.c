/* Project: Parallel Attack Graph Generator (OpenMP)
 * File name: main.c
 * Author: Ming Li Email: mingfinkli@gmail.com
 * Description:
This is the c file with main function:
- read and parse input data
- populate attach graph instance with input data
- call the attack graph generator() function
- report the main features of the output attack graph
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h> 
#include <stdbool.h>
#include <sys/time.h>
#include "main.h"
#include "ag_gen.h"

#define maxNumEntries 500
#define first_prime 1000003
#define second_prime 999983

void generator(AGGenDigitInstance *digitInstance);

/*define arrays to store input data*/
assetStruct aVec[maxNumEntries]; // asset array
qualityStruct qVec[maxNumEntries]; // initial quality array
topologyStruct tVec[maxNumEntries]; // initial topology array
exploitStruct eVec[maxNumEntries]; // exploit array
exploit_preconditionStruct preVec[maxNumEntries]; // exploit-precondition array
exploit_postconditionStruct postVec[maxNumEntries]; // exploit-postcondition array

int aVecSize=0;
int qVecSize=0;
int tVecSize=0;
int eVecSize=0;
int preVecSize=0;
int postVecSize=0;


int numThreads;
int initQSize;

hashItem factsHashTable[first_prime];
hashItem assetFactsHashTable[first_prime];
hashItem precondFactsHashTable[first_prime];
hashItem exploitFactsHashTable[first_prime];    

char* find_next(char * startAddr, char * targetStr){
    return strstr(startAddr, targetStr);
}

/* parse the text read from the input file: *.data*/
void parseInputStr(char* recvStr){
  char* posA=strstr(recvStr, "INSERT INTO asset VALUES");
  char* posQ=strstr(recvStr, "INSERT INTO quality VALUES");
  char* posT=strstr(recvStr, "INSERT INTO topology VALUES");
  char* posE=strstr(recvStr, "INSERT INTO exploit VALUES");
  char* posPre=strstr(recvStr, "INSERT INTO exploit_precondition VALUES");
  char* posPost=strstr(recvStr, "INSERT INTO exploit_postcondition VALUES");
  printf("The 6 index values are: %ld %ld %ld %ld %ld %ld \n",posA-posA, posQ-posA, posT-posA, posE-posA, posPre-posA, posPost-posA);
  
  //parse the asset entries
  printf("----------Parse the asset string---------\n");
  char* currPos=posA;
  for(;;){
    char * nextPos1=find_next(currPos, "(");//asset id position
    if(nextPos1>posQ) break;
    currPos=nextPos1+1;
    char * nextPos2=find_next(currPos, ",");
    currPos=nextPos2+1;
    char * nextPos3=find_next(currPos, "'");//asset name position
    currPos=nextPos3+1;
    char * nextPos4=find_next(currPos, "'");
    currPos=nextPos4+1; //to start the next line
    assetStruct aBuf;
    strncpy(aBuf.id, nextPos1+1, nextPos2-nextPos1-1);
    aBuf.id[nextPos2-nextPos1-1]='\0';
    strncpy(aBuf.name, nextPos3+1, nextPos4-nextPos3-1);
    aBuf.name[nextPos4-nextPos3-1]='\0';
    aVec[aVecSize] = aBuf;
    aVecSize++;
  }
  printf("---number of assets %d\n", aVecSize);
  for(int i=0;i<aVecSize;i++){
    printf("id: %s name: %s\n", aVec[i].id, aVec[i].name);
  }
  //parse the quality entries
  printf("-----------Parse the quality string---------\n");
  currPos=posQ;
  for(;;){
    char * nextPos1=find_next(currPos, "(");
    if(nextPos1>posT) break;
    currPos=nextPos1+1;
    char * nextPos2=find_next(currPos, ",");
    currPos=nextPos2+1;
    char * nextPos3=find_next(currPos, "'");
    currPos=nextPos3+1;
    char * nextPos4=find_next(currPos, "'");
    currPos=nextPos4+1;
    char * nextPos5=find_next(currPos, "'");
    currPos=nextPos5+1;
    char * nextPos6=find_next(currPos, "'");
    currPos=nextPos6+1;
    char * nextPos7=find_next(currPos, "'");
    currPos=nextPos7+1;
    char * nextPos8=find_next(currPos, "'");
    currPos=nextPos8+1;
    qualityStruct qBuf;
    strncpy(qBuf.asset_id, nextPos1+1, nextPos2-nextPos1-1);
    qBuf.asset_id[nextPos2-nextPos1-1]='\0';
    strncpy(qBuf.property, nextPos3+1, nextPos4-nextPos3-1);
    qBuf.property[nextPos4-nextPos3-1]='\0';
    strncpy(qBuf.op, nextPos5+1, nextPos6-nextPos5-1);
    qBuf.op[nextPos6-nextPos5-1]='\0';
    strncpy(qBuf.value, nextPos7+1, nextPos8-nextPos7-1);
    qBuf.value[nextPos8-nextPos7-1]='\0';
    qVec[qVecSize]=qBuf;
    qVecSize++;    
  }
  printf("---number of initial qualities %d\n", qVecSize);
  for(int i=0;i<qVecSize;i++){
    printf("asset_id: %s property: %s op: %s value: %s\n", qVec[i].asset_id, qVec[i].property, qVec[i].op, qVec[i].value);
  }
  //parse the topology entries
  printf("-----------Parse the topology string---------\n");
  currPos=posT;
  for(;;){
    char* nextPos1=find_next(currPos, "(");
    if(nextPos1>posE) break;
    currPos=nextPos1+1;
    char* nextPos2=find_next(currPos, ",");
    currPos=nextPos2+1;
    char* nextPos3=find_next(currPos, " ");
    currPos=nextPos3+1;
    char* nextPos4=find_next(currPos, ",");
    currPos=nextPos4+1;
    char* nextPos5=find_next(currPos, "'");
    currPos=nextPos5+1;
    char* nextPos6=find_next(currPos, "'");
    currPos=nextPos6+1;
    char* nextPos7=find_next(currPos, "'");
    currPos=nextPos7+1;
    char* nextPos8=find_next(currPos, "'");
    currPos=nextPos8+1;
    char* nextPos9=find_next(currPos, "'");
    currPos=nextPos9+1;
    char* nextPos10=find_next(currPos, "'");
    currPos=nextPos10+1;
    char* nextPos11=find_next(currPos, "'");
    currPos=nextPos11+1;
    char* nextPos12=find_next(currPos, "'");
    currPos=nextPos12+1;
    topologyStruct tBuf;
    strncpy(tBuf.asset_from_id, nextPos1+1, nextPos2-nextPos1-1);
    tBuf.asset_from_id[nextPos2-nextPos1-1]='\0';
    strncpy(tBuf.asset_to_id, nextPos3+1, nextPos4-nextPos3-1);
    tBuf.asset_to_id[nextPos4-nextPos3-1]='\0';
    strncpy(tBuf.direction, nextPos5+1, nextPos6-nextPos5-1);
    tBuf.direction[nextPos6-nextPos5-1]='\0';
    strncpy(tBuf.property, nextPos7+1, nextPos8-nextPos7-1);
    tBuf.property[nextPos8-nextPos7-1]='\0';    
    strncpy(tBuf.op, nextPos9+1, nextPos10-nextPos9-1);
    tBuf.op[nextPos10-nextPos9-1]='\0';
    strncpy(tBuf.value, nextPos11+1, nextPos12-nextPos11-1);
    tBuf.value[nextPos12-nextPos11-1]='\0';
    tVec[tVecSize]=tBuf;    
    tVecSize++;
  }
  printf("---number of topologies %d\n", tVecSize);
  for(int i=0;i<tVecSize;i++){
    //std::cout<<tVec[i].asset_from_id<<"||"<<tVec[i].asset_to_id<<"||"<<tVec[i].direction<<"||"<<tVec[i].property<<"||"<<tVec[i].op<<"||"<<tVec[i].value<<"\n";
    printf("%s||%s||%s||%s||%s||%s\n", tVec[i].asset_from_id, tVec[i].asset_to_id, tVec[i].direction, tVec[i].property, tVec[i].op, tVec[i].value); 
  }
  //parse the exploit entries
  printf("-----------Parse the exploit string---------\n");
  currPos=posE;
  for(;;){
    char* nextPos1=find_next(currPos, "(");
    if(nextPos1>posPre) break;
    currPos=nextPos1+1;
    char* nextPos2=find_next(currPos, ",");
    currPos=nextPos2+1;
    char* nextPos3=find_next(currPos, "'");
    currPos=nextPos3+1;
    char* nextPos4=find_next(currPos, "'");
    currPos=nextPos4+1;
    char* nextPos5=find_next(currPos, " ");
    currPos=nextPos5+1;
    char* nextPos6=find_next(currPos, ")");
    currPos=nextPos6+1;
    exploitStruct eBuf;
    strncpy(eBuf.id, nextPos1+1, nextPos2-nextPos1-1);
    eBuf.id[nextPos2-nextPos1-1]='\0';
    strncpy(eBuf.name, nextPos3+1, nextPos4-nextPos3-1);
    eBuf.name[nextPos4-nextPos3-1]='\0';
    strncpy(eBuf.params, nextPos5+1, nextPos6-nextPos5-1);
    eBuf.params[nextPos6-nextPos5-1]='\0';
    eVec[eVecSize]=eBuf;
    eVecSize++;
  }
  printf("---number of exploits %d\n", eVecSize);
  for(int i=0;i<eVecSize;i++){
    printf("id: %s name: %s params: %s\n", eVec[i].id, eVec[i].name, eVec[i].params);
  }
  //parse the exploit-precondition entries
  printf("-----------Parse the exploit precondition string---------\n");
  currPos=posPre;
  for(;;){
    char* nextPos1=find_next(currPos, "(");
    if(nextPos1>posPost) break;
    currPos=nextPos1+1;
    char* nextPos2=find_next(currPos, ",");
    currPos=nextPos2+1;
    char* nextPos3=find_next(currPos, " ");
    currPos=nextPos3+1;
    char* nextPos4=find_next(currPos, ",");
    currPos=nextPos4+1;
    char* nextPos5=find_next(currPos, " ");
    currPos=nextPos5+1;
    char* nextPos6=find_next(currPos, ",");
    currPos=nextPos6+1;
    char* nextPos7=find_next(currPos, " ");
    currPos=nextPos7+1;
    char* nextPos8=find_next(currPos, ",");
    currPos=nextPos8+1;
    char* nextPos9=find_next(currPos, " ");
    currPos=nextPos9+1;
    char* nextPos10=find_next(currPos, ",");
    currPos=nextPos10+1;
    char* nextPos11=find_next(currPos, "'");
    currPos=nextPos11+1;
    char* nextPos12=find_next(currPos, "'");
    currPos=nextPos12+1;
    char* nextPos13=find_next(currPos, "'");
    currPos=nextPos13+1;
    char* nextPos14=find_next(currPos, "'");
    currPos=nextPos14+1;
    char* nextPos15=find_next(currPos, "'");
    currPos=nextPos15+1;
    char* nextPos16=find_next(currPos, "'");
    currPos=nextPos16+1;
    char* nextPos17=find_next(currPos, "'");
    currPos=nextPos17+1;
    char* nextPos18=find_next(currPos, "'");
    currPos=nextPos18+1;
    exploit_preconditionStruct preBuf;
    strncpy(preBuf.id, nextPos1+1, nextPos2-nextPos1-1);
    preBuf.id[nextPos2-nextPos1-1]='\0';
    strncpy(preBuf.exploit_id, nextPos3+1, nextPos4-nextPos3-1);
    preBuf.exploit_id[nextPos4-nextPos3-1]='\0';
    strncpy(preBuf.type, nextPos5+1, nextPos6-nextPos5-1);
    preBuf.type[nextPos6-nextPos5-1]='\0';
    strncpy(preBuf.param1, nextPos7+1, nextPos8-nextPos7-1);
    preBuf.param1[nextPos8-nextPos7-1]='\0';    
    strncpy(preBuf.param2, nextPos9+1, nextPos10-nextPos9-1);
    preBuf.param2[nextPos10-nextPos9-1]='\0';
    strncpy(preBuf.property, nextPos11+1, nextPos12-nextPos11-1);
    preBuf.property[nextPos12-nextPos11-1]='\0';    
    strncpy(preBuf.value, nextPos13+1, nextPos14-nextPos13-1);
    preBuf.value[nextPos14-nextPos13-1]='\0';    
    strncpy(preBuf.op, nextPos15+1, nextPos16-nextPos15-1);
    preBuf.op[nextPos16-nextPos15-1]='\0';
    strncpy(preBuf.dir, nextPos17+1, nextPos18-nextPos17-1);
    preBuf.dir[nextPos18-nextPos17-1]='\0';
    preVec[preVecSize]=preBuf;    
    preVecSize++;
  }
  printf("---number of precondition entries %d\n", preVecSize); 
  for(int i=0;i<preVecSize;i++){
    printf("%s||%s||%s||%s||%s||%s||%s||%s||%s\n", preVec[i].id, preVec[i].exploit_id, preVec[i].type, preVec[i].param1, preVec[i].param2, preVec[i].property, preVec[i].value, preVec[i].op, preVec[i].dir);   
  }
  //parse the exploit-postcondition entries
  printf("-----------Parse the exploit postcondition string---------\n");
  currPos=posPost;
  for(;;){
    char* nextPos1=find_next(currPos, "(");
    currPos=nextPos1+1;
    char* nextPos2=find_next(currPos, ",");
    currPos=nextPos2+1;
    char* nextPos3=find_next(currPos, " ");
    currPos=nextPos3+1;
    char* nextPos4=find_next(currPos, ",");
    currPos=nextPos4+1;
    char* nextPos5=find_next(currPos, " ");
    currPos=nextPos5+1;
    char* nextPos6=find_next(currPos, ",");
    currPos=nextPos6+1;
    char* nextPos7=find_next(currPos, " ");
    currPos=nextPos7+1;
    char* nextPos8=find_next(currPos, ",");
    currPos=nextPos8+1;
    char* nextPos9=find_next(currPos, " ");
    currPos=nextPos9+1;
    char* nextPos10=find_next(currPos, ",");
    currPos=nextPos10+1;
    char* nextPos11=find_next(currPos, "'");
    currPos=nextPos11+1;
    char* nextPos12=find_next(currPos, "'");
    currPos=nextPos12+1;
    char* nextPos13=find_next(currPos, "'");
    currPos=nextPos13+1;
    char* nextPos14=find_next(currPos, "'");
    currPos=nextPos14+1;
    char* nextPos15=find_next(currPos, "'");
    currPos=nextPos15+1;
    char* nextPos16=find_next(currPos, "'");
    currPos=nextPos16+1;
    char* nextPos17=find_next(currPos, "'");
    currPos=nextPos17+1;
    char* nextPos18=find_next(currPos, "'");
    currPos=nextPos18+1;
    char* nextPos19=find_next(currPos, "'");
    currPos=nextPos19+1;
    char* nextPos20=find_next(currPos, "'");
    currPos=nextPos20+2;
    exploit_postconditionStruct postBuf;
    strncpy(postBuf.id,nextPos1+1,nextPos2-nextPos1-1);
    postBuf.id[nextPos2-nextPos1-1]='\0';
    strncpy(postBuf.exploit_id,nextPos3+1,nextPos4-nextPos3-1);
    postBuf.exploit_id[nextPos4-nextPos3-1]='\0';
    strncpy(postBuf.type,nextPos5+1,nextPos6-nextPos5-1);
    postBuf.type[nextPos6-nextPos5-1]='\0';
    strncpy(postBuf.param1,nextPos7+1,nextPos8-nextPos7-1);
    postBuf.param1[nextPos8-nextPos7-1]='\0';    
    strncpy(postBuf.param2,nextPos9+1,nextPos10-nextPos9-1);
    postBuf.param2[nextPos10-nextPos9-1]='\0';
    strncpy(postBuf.property,nextPos11+1,nextPos12-nextPos11-1); 
    postBuf.property[nextPos12-nextPos11-1]='\0';   
    strncpy(postBuf.value,nextPos13+1,nextPos14-nextPos13-1);
    postBuf.value[nextPos14-nextPos13-1]='\0';    
    strncpy(postBuf.op,nextPos15+1,nextPos16-nextPos15-1);
    postBuf.op[nextPos16-nextPos15-1]='\0';
    strncpy(postBuf.dir,nextPos17+1,nextPos18-nextPos17-1);
    postBuf.dir[nextPos18-nextPos17-1]='\0';    
    strncpy(postBuf.action,nextPos19+1,nextPos20-nextPos19-1);
    postBuf.action[nextPos20-nextPos19-1]='\0';
    postVec[postVecSize]=postBuf;
    postVecSize++;
    if((*currPos)==';'){
        printf("End of the entire string\n"); 
        break; //the postcondition string has a different condition to exit the for loop
    }
  }
  printf("---number of postcondition entries %d\n", postVecSize);
  for(int i=0;i<postVecSize;i++){
    printf("%s||%s||%s||%s||%s||%s||%s||%s||%s||%s\n", postVec[i].id, postVec[i].exploit_id, postVec[i].type, postVec[i].param1, postVec[i].param2, postVec[i].property, postVec[i].value, postVec[i].op, postVec[i].dir, postVec[i].action); 
  }
}


/*read input file *.data into memory*/
char* receive_input(char *filename){
  static char tData[200000]; //adjust the size of this array to accommodate different input files
  FILE *fp=fopen(filename,"r");
  int i=0;
  while(feof(fp)==0){
      tData[i]=fgetc(fp);
      i++;
  }
  printf("The last symbol from the input file is %c\n", tData[i-1]);
  tData[i-1]='\0';
  fclose(fp);
  return(tData);
}


unsigned int hfunc1(unsigned int key) 
{
    unsigned int M=first_prime; 
    return (key%M); 
} 

unsigned int hfunc2(unsigned int key) 
{
    unsigned int R=second_prime;
    return (R-(key%R)); 
}

int hashSave(unsigned int key, hashItem* hTable, int sNum){
    unsigned int index=hfunc1(key);
    if (hTable[index].unitState==0) //empty bucket, save directly
    {
        hTable[index].hValue = key;
        hTable[index].seqNum = sNum;
        hTable[index].unitState = 1;
        return 0; //return 0 to indicate no collision during saving
    }
    else{ 
        if (hTable[index].hValue==key) {
            return -1; //the key is already stored in the hTable
        }
        else {  
            unsigned int index2 = hfunc2(key); //double hashing's second index 
            int i = 1;//starting from collision 1 
            while(true){ 
                // get newIndex 
                unsigned int newIndex = (index+i*index2)%first_prime; 
            
                if (hTable[newIndex].unitState==0) {//empty bucket, save after i collisions
                    hTable[newIndex].hValue = key;
                    hTable[newIndex].seqNum = sNum;
                    hTable[newIndex].unitState = 1; //occupied unit
                    return i;
                }
                else{ 
                    if (hTable[newIndex].hValue==key) {//the key is already stored in the hTable
                        return -1;
                    }
                    else{
                        i++;
                    }
                }
            } 
        }
    }   
}

int hashSearch(unsigned int key, hashItem* hTable){
    unsigned int index=hfunc1(key);
    if (hTable[index].unitState==0) //empty bucket, search miss
    {
        return -1; //return -1 to indicate a search miss
    }
    else{ 
        if (hTable[index].hValue==key) {
            return hTable[index].seqNum; //a direct search hit
        }
        else {  
            unsigned int index2 = hfunc2(key); //double hashing's second index 
            int i = 1;//starting from collision 1 
            while(true){ 
                // get newIndex 
                unsigned int newIndex = (index+i*index2)%first_prime; 
            
                if (hTable[newIndex].unitState==0) {//empty bucket, save after i collisions
                    return -1; //return -1 to indicate a miss
                }
                else{ 
                    if (hTable[newIndex].hValue==key) {//the key is already stored in the hTable
                        return hTable[newIndex].seqNum; //return i to indicate an indirect search hit
                    }
                    else{
                        i++;
                    }
                }
            } 
        }
    }   
}

//jenkins_one_at_a_time_hash function to compute hash value for each c string
unsigned int jHash(char *key, size_t len)
{
    unsigned int hash, i;
    for(hash = i = 0; i < len; ++i)
    {
        hash += key[i];
        hash += (hash << 10);
        hash ^= (hash >> 6);
    }
    hash += (hash << 3);
    hash ^= (hash >> 11);
    hash += (hash << 15);
    return hash;
}

void resetHashTables(){
    for(int i=0; i<first_prime; i++){
        assetFactsHashTable[i].unitState = 0;
        factsHashTable[i].unitState = 0;
        precondFactsHashTable[i].unitState = 0;
        exploitFactsHashTable[i].unitState = 0;
    }
}

void hashAllFacts(){
    unsigned int key;
    //assetFactsHashTable
    int sNum = 0;
    for(int i=0; i<aVecSize; i++){
        key = jHash(aVec[i].name, strlen(aVec[i].name));
        if(hashSave(key, assetFactsHashTable, sNum)!=-1) sNum++;
    }
    printf("number of unique asset facts %d\n", sNum);
    //factsHashTable
    sNum = 0;
    for(int i=0; i<qVecSize; i++){
        key = jHash(qVec[i].property, strlen(qVec[i].property));
        if(hashSave(key, factsHashTable, sNum)!=-1) sNum++;
        key = jHash(qVec[i].value, strlen(qVec[i].value));
        if(hashSave(key, factsHashTable, sNum)!=-1) sNum++;
    }
    for(int i=0; i<postVecSize; i++){
        key = jHash(postVec[i].property, strlen(postVec[i].property));
        if(hashSave(key, factsHashTable, sNum)!=-1) sNum++;
        key = jHash(postVec[i].value, strlen(postVec[i].value));
        if(hashSave(key, factsHashTable, sNum)!=-1) sNum++;
    }
    for(int i=0; i<tVecSize; i++){
        key = jHash(tVec[i].property, strlen(tVec[i].property));
        if(hashSave(key, factsHashTable, sNum)!=-1) sNum++;
        key = jHash(tVec[i].value, strlen(tVec[i].value));
        if(hashSave(key, factsHashTable, sNum)!=-1) sNum++;
    }
    for(int i=0; i<preVecSize; i++){
        key = jHash(preVec[i].property, strlen(preVec[i].property));
        if(hashSave(key, factsHashTable, sNum)!=-1) sNum++;
        if((strcmp(preVec[i].op, "<")!=0) && (strcmp(preVec[i].op, "<=")!=0) && (strcmp(preVec[i].op, ">")!=0) && (strcmp(preVec[i].op, ">=")!=0)){
            key = jHash(preVec[i].value, strlen(preVec[i].value));
            if(hashSave(key, factsHashTable, sNum)!=-1) sNum++;
        }
    }
    printf("number of unique facts %d\n", sNum);
    //precondFactsHashTable
    sNum=0;
    for(int i=0; i<preVecSize; i++){
        key = jHash(preVec[i].property, strlen(preVec[i].property));
        if(hashSave(key, precondFactsHashTable, sNum)!=-1) sNum++;
        key = jHash(preVec[i].value, strlen(preVec[i].value));
        if(hashSave(key, precondFactsHashTable, sNum)!=-1) sNum++;
    }
    printf("number of unique precond facts %d\n", sNum);
    //exploitFactsHashTable
    sNum=0;
    for(int i=0; i<eVecSize; i++){
        key = jHash(eVec[i].name, strlen(eVec[i].name));
        if(hashSave(key, exploitFactsHashTable, sNum)!=-1) sNum++;
    }
    printf("number of unique exploit facts %d\n", sNum);
}

int getAssetNumQ(int id){
    int numQ = 0;
    for(int i=0; i<qVecSize; i++){
        if(strcmp(aVec[id].id, qVec[i].asset_id)==0) numQ++;
    }
    return numQ;
}

int getNumPreQ(int id){
    int numPreQ = 0;
    for(int i=0; i<preVecSize; i++){
        if(strcmp(eVec[id].id, preVec[i].exploit_id)==0 && strcmp(preVec[i].type, "0")==0) numPreQ++; 
    }
    return numPreQ;
}

int getNumPreT(int id){
    int numPreT = 0;
    for(int i=0; i<preVecSize; i++){
        if(strcmp(eVec[id].id, preVec[i].exploit_id)==0 && strcmp(preVec[i].type, "1")==0) numPreT++;  
    }
    return numPreT;
}

int getNumPostQ(int id){
    int numPostQ = 0;
    for(int i=0; i<postVecSize; i++){
        if(strcmp(eVec[id].id, postVec[i].exploit_id)==0 && strcmp(postVec[i].type, "0")==0) numPostQ++;  
    }
    return numPostQ;
}

int getNumPostT(int id){
    int numPostT = 0;
    for(int i=0; i<postVecSize; i++){
        if(strcmp(eVec[id].id, postVec[i].exploit_id)==0 && strcmp(postVec[i].type, "1")==0) numPostT++;  
    }
    return numPostT;
}

bool isFloat(char* string1){
    bool decimalPoint = false;
    int it=0;
    if(strlen(string1)>0 && (string1[0] == '-' || string1[0] == '+')){
      it++;
    }
    while(it != strlen(string1)){
      if(string1[it] == '.'){
        if(!decimalPoint) decimalPoint = true;
        else return false;
      }
      else if(string1[it]<48 || string1[it]>57){
        return false;
      }
      ++it;
    }
    return true;
}

void getExploitPreQ(int id, AGGenDigitInstance *instance){
    int j=0;
    for(int i=0; i<preVecSize; i++){
        if(strcmp(eVec[id].id, preVec[i].exploit_id)==0 && strcmp(preVec[i].type, "0")==0){
            (*instance).exploits[id].preQ[j].param1 = strtol(preVec[i].param1, NULL, 10);
            (*instance).exploits[id].preQ[j].property = hashSearch(jHash(preVec[i].property, strlen(preVec[i].property)), factsHashTable);
            (*instance).exploits[id].preQ[j].value = hashSearch(jHash(preVec[i].value, strlen(preVec[i].value)), factsHashTable);
            if(strcmp(preVec[i].op, "=")==0 || strcmp(preVec[i].op, "==")==0 || strcmp(preVec[i].op, ":=")==0){//attack graph is discrete
                (*instance).exploits[id].preQ[j].op = 0;
                (*instance).exploits[id].preQ[j].type = 0;
                (*instance).exploits[id].preQ[j].fvalue = 0.0;
            }
            else{//attack graph is hybrid
                (*instance).exploits[id].preQ[j].type = 1;
                if(strcmp(preVec[i].op, ">")==0) (*instance).exploits[id].preQ[j].op=1;
                else if(strcmp(preVec[i].op, ">=")==0) (*instance).exploits[id].preQ[j].op=2;
                else if(strcmp(preVec[i].op, "<")==0) (*instance).exploits[id].preQ[j].op=3;
                else if(strcmp(preVec[i].op, "<=")==0) (*instance).exploits[id].preQ[j].op=4;
                (*instance).exploits[id].preQ[j].fvalue = strtof(preVec[i].value, NULL);
            }
            j++;
        }
    } 
}

void getExploitPreT(int id, AGGenDigitInstance *instance){
    int j=0;
    for(int i=0; i<preVecSize; i++){
        if(strcmp(eVec[id].id, preVec[i].exploit_id)==0 && strcmp(preVec[i].type, "1")==0){
            (*instance).exploits[id].preT[j].param1 = strtol(preVec[i].param1, NULL, 10);
            (*instance).exploits[id].preT[j].param2 = strtol(preVec[i].param2, NULL, 10);
            (*instance).exploits[id].preT[j].property = hashSearch(jHash(preVec[i].property, strlen(preVec[i].property)), factsHashTable);
            if(strcmp(preVec[i].dir, "->")==0) (*instance).exploits[id].preT[j].dir = 0;
            else if(strcmp(preVec[i].dir, "<-")==0) (*instance).exploits[id].preT[j].dir = 1;
            else if(strcmp(preVec[i].dir, "<->")==0) (*instance).exploits[id].preT[j].dir = 2;
            j++;
        }
    } 
}

void getExploitPostQ(int id, AGGenDigitInstance *instance){
    int j=0;
    for(int i=0; i<postVecSize; i++){
        if(strcmp(eVec[id].id, postVec[i].exploit_id)==0 && strcmp(postVec[i].type, "0")==0){
            (*instance).exploits[id].postQ[j].param1 = strtol(postVec[i].param1, NULL, 10);
            (*instance).exploits[id].postQ[j].property = hashSearch(jHash(postVec[i].property, strlen(postVec[i].property)), factsHashTable);
            (*instance).exploits[id].postQ[j].value = hashSearch(jHash(postVec[i].value, strlen(postVec[i].value)), factsHashTable);
            (*instance).exploits[id].postQ[j].op=0;
            if(strcmp(postVec[i].action, "add")==0 || strcmp(postVec[i].action, "insert")==0)
            (*instance).exploits[id].postQ[j].action = 0;
            else if(strcmp(postVec[i].action, "update")==0)
            (*instance).exploits[id].postQ[j].action = 1; 
            else if(strcmp(postVec[i].action, "delete")==0)
            (*instance).exploits[id].postQ[j].action = 2;
            if(isFloat(postVec[i].value)) (*instance).exploits[id].postQ[j].fvalue = strtof(postVec[i].value, NULL);
            else (*instance).exploits[id].postQ[j].fvalue = 0.0;             
            j++;
        }
    } 
}

void getExploitPostT(int id, AGGenDigitInstance *instance){
    int j=0;
    for(int i=0; i<postVecSize; i++){
        if(strcmp(eVec[id].id, postVec[i].exploit_id)==0 && strcmp(postVec[i].type, "1")==0){
            (*instance).exploits[id].postT[j].param1 = strtol(postVec[i].param1, NULL, 10);
            (*instance).exploits[id].postT[j].param2 = strtol(postVec[i].param2, NULL, 10);
            (*instance).exploits[id].postT[j].property = hashSearch(jHash(postVec[i].property, strlen(postVec[i].property)), factsHashTable);
            if(strcmp(postVec[i].dir, "->")==0) (*instance).exploits[id].postT[j].dir = 0;
            else if(strcmp(postVec[i].dir, "<-")==0) (*instance).exploits[id].postT[j].dir = 1;
            else if(strcmp(postVec[i].dir, "<->")==0) (*instance).exploits[id].postT[j].dir = 2;
            if(strcmp(postVec[i].action, "add")==0 || strcmp(postVec[i].action, "insert")==0)
            (*instance).exploits[id].postT[j].action = 0;
            else if(strcmp(postVec[i].action, "update")==0)
            (*instance).exploits[id].postT[j].action = 1; 
            else if(strcmp(postVec[i].action, "delete")==0)
            (*instance).exploits[id].postT[j].action = 2;
            j++;
        }
    } 
}

/* fill an empty AG instance with input data */
void populateDigitInstance(AGGenDigitInstance *instance){
    //fill assets
    (*instance).numOfAssets = aVecSize;
    for(int i=0;i<(*instance).numOfAssets;i++){
        (*instance).assets[i].asset_name=hashSearch(jHash(aVec[i].name, strlen(aVec[i].name)), assetFactsHashTable);
        (*instance).assets[i].num_Q=getAssetNumQ(i);
    }
    //fill initial qualities
    (*instance).numOfInitQualities = qVecSize;
    for(int i=0;i<(*instance).numOfInitQualities;i++){
        (*instance).initial_qualities[i].asset_id=strtol(qVec[i].asset_id, NULL, 10);
        (*instance).initial_qualities[i].property=hashSearch(jHash(qVec[i].property, strlen(qVec[i].property)), factsHashTable);
        if(strcmp(qVec[i].op, "=") == 0)
            (*instance).initial_qualities[i].op=0;
        else if(strcmp(qVec[i].op, ":=") == 0)
            (*instance).initial_qualities[i].op=0;
        (*instance).initial_qualities[i].value = hashSearch(jHash(qVec[i].value, strlen(qVec[i].value)), factsHashTable);
        if(isFloat(qVec[i].value))
        (*instance).initial_qualities[i].fvalue=strtof(qVec[i].value, NULL);
        else
        (*instance).initial_qualities[i].fvalue=0.0;
    }
    //fill initial topologies
    (*instance).numOfInitTopologies=tVecSize;
    for(int i=0;i<(*instance).numOfInitTopologies;i++){
        (*instance).initial_topologies[i].from_asset_id = strtol(tVec[i].asset_from_id, NULL, 10);
        (*instance).initial_topologies[i].to_asset_id = strtol(tVec[i].asset_to_id, NULL, 10);
        (*instance).initial_topologies[i].property = hashSearch(jHash(tVec[i].property, strlen(tVec[i].property)), factsHashTable);
        if(strcmp(tVec[i].direction, "->")==0) 
        (*instance).initial_topologies[i].dir=0;
        else if(strcmp(tVec[i].direction, "<-")==0) 
        (*instance).initial_topologies[i].dir=1;
        else if(strcmp(tVec[i].direction, "<->")==0) 
        (*instance).initial_topologies[i].dir=2;
    }
    //fill exploits, and pre- and post-conditions
    (*instance).numOfExploits=eVecSize;
    for(int i=0;i<(*instance).numOfExploits;i++){
        (*instance).exploits[i].id = strtol(eVec[i].id, NULL, 10);
        (*instance).exploits[i].name = hashSearch(jHash(eVec[i].name, strlen(eVec[i].name)), exploitFactsHashTable);
        (*instance).exploits[i].num_params = strtol(eVec[i].params, NULL, 10);
        (*instance).exploits[i].num_preQ = getNumPreQ(i);
        (*instance).exploits[i].num_preT = getNumPreT(i);
        (*instance).exploits[i].num_postQ = getNumPostQ(i);
        (*instance).exploits[i].num_postT = getNumPostT(i);
        getExploitPreQ(i, instance);
        getExploitPreT(i, instance);
        getExploitPostQ(i, instance);
        getExploitPostT(i, instance);      
    }
}

int main(int argc, char *argv[]) {
    //------------------------------
    // initialization and database connection
    //------------------------------

    printf(">>>>>>>>>>> step 1: check control parameters ...\n");    
    numThreads = strtol(argv[2],NULL,10);
    initQSize = strtol(argv[4],NULL,10);
    printf("%d %d\n", numThreads, initQSize);
    char *filename = argv[6];
    printf("The file name is %s\n", filename);
 
    struct timeval ts1,tf1,ts2,tf2,ts3,tf3;
    gettimeofday(&ts1,NULL);
    if (argc < 4) {
        printf("parameters needed for command line input!\n");
	//for main
        return 0;
    }
    printf(">>>>>>>>>>>>> Step 1: done\n");
    printf("\n");

    //--------------------------------------------
    // read the network model and exploit patterns from an external file into memory
    //--------------------------------------------

    printf(">>>>>>>>>>>>>>>>> Step 2: load in nm and xp\n");
    gettimeofday(&ts3,NULL);
    char* inputStr=receive_input(filename);
    gettimeofday(&tf3,NULL);
    double tdiff3=(tf3.tv_sec-ts3.tv_sec)*1000.0+(tf3.tv_usec-ts3.tv_usec)/1000.0;
    printf("The length of the input string is %ld\n",strlen(inputStr));    
    printf("The time to load the input string is %lf ms.<------\n",tdiff3);
    printf("====== The contents in inputStr: ======\n");
    printf("%s\n", inputStr);
    printf("=======================================\n");
    printf(">>>>>>>>>>>> Step 2: done\n");
    printf("\n");


    //------------------------------------------
    // parse the c string of the network model and exploit patterns
    //------------------------------------------
    //The following vectors are prepared by this step
    //std::vector<assetStruct> aVec;
    //std::vector<qualityStruct> qVec; 
    //std::vector<topologyStruct> tVec;
    //std::vector<exploitStruct> eVec;
    //std::vector<exploit_preconditionStruct> preVec;
    //std::vector<exploit_postconditionStruct> postVec;
    //----------- functions being used -------------
    //parseInputStr() defined in this file

    printf(">>>>>>>>>>>>>>>>> Step 3: parse the input model\n");
    parseInputStr(inputStr);
    printf(">>>>>>>>>>>>>>>>> Step 3: done\n");
    printf("\n"); 

    //------------------------------------------
    // Populate AG instance with input data 
    //------------------------------------------
    printf(">>>>>>>>>>>>>>>>> Step 4: create an AG instance and populate it with input data\n");
    AGGenDigitInstance* instance=(AGGenDigitInstance *)malloc(sizeof(AGGenDigitInstance));
    printf("--- The size of the created AG instance is %ld\n", sizeof(AGGenDigitInstance));
    printf("\n");

    printf("--- Hashing all facts ...\n");
    resetHashTables();
    hashAllFacts();
    printf("--- Hashing done !!!\n");
    printf("\n");

    printf("--- Populating the AG instance with initial data ... \n");
    populateDigitInstance(instance);
    printf("#digitized qualities: \n");
    for(int i=0; i<(*instance).numOfInitQualities; i++){
        printf("%d %d %d %d %f\n", (*instance).initial_qualities[i].asset_id, (*instance).initial_qualities[i].property, (*instance).initial_qualities[i].op, (*instance).initial_qualities[i].value, (*instance).initial_qualities[i].fvalue);
    }
    printf("#digitized topologies: \n");
    for(int i=0; i<(*instance).numOfInitTopologies; i++){
        printf("%d %d %d %d\n", (*instance).initial_topologies[i].from_asset_id, (*instance).initial_topologies[i].to_asset_id, (*instance).initial_topologies[i].property, (*instance).initial_topologies[i].dir);
    }
    printf("#digitized exploits: \n");
    for(int i=0;i<(*instance).numOfExploits;i++){
        printf("%d %d %d %d %d %d %d\n", (*instance).exploits[i].id, (*instance).exploits[i].name, (*instance).exploits[i].num_params, (*instance).exploits[i].num_preQ, (*instance).exploits[i].num_preT, (*instance).exploits[i].num_postQ, (*instance).exploits[i].num_postT);        
    }
    printf("#sample exploit-precondition qualities\n");
    for(int i=0;i<(*instance).numOfExploits;i++){
        printf("Exploit %d --- %d %d %d %d %d %f\n", i, (*instance).exploits[i].preQ[0].param1, (*instance).exploits[i].preQ[0].property, (*instance).exploits[i].preQ[0].value, (*instance).exploits[i].preQ[0].op, (*instance).exploits[i].preQ[0].type, (*instance).exploits[i].preQ[0].fvalue);
    }
    printf("#sample exploit-postcondition qualities\n");
    for(int i=0;i<(*instance).numOfExploits;i++){
        printf("Exploit %d --- %d %d %d %d %d %f\n", i, (*instance).exploits[i].postQ[0].param1, (*instance).exploits[i].postQ[0].property, (*instance).exploits[i].postQ[0].value, (*instance).exploits[i].postQ[0].op, (*instance).exploits[i].postQ[0].action, (*instance).exploits[i].postQ[0].fvalue);  
    }
    printf("--- Populating done !!!\n");
    printf(">>>>>>>>>>>>>>>>> Step 4: done\n");
    printf("\n");



    //------------------------------------------
    // Generate attack graph
    //------------------------------------------    
    printf(">>>>>>>>>>>>>>>>> Step 5: generate the AG\n");
    
    generator(instance);
    printf(">>>>>>>>>>>>>>>>> Step 5: done\n");
    return(0);
}
