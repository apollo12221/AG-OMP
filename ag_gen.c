/* Project: Parallel Attack Graph Generator (OpenMP)
 * File name: ag_gen.c
 * Author: Ming Li 
 * Email: mingfinkli@gmail.com
 * Description:
This is the c file with generator function:
- generate and return the attack graph
- report performance data and graph features
*/

#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include "ag_gen.h"
#include <omp.h>

/* a struct type to define a variable storing a valid binding of exploits and assets*/
typedef struct {
    char ex_id;
    char num_params;
    short perm[3];   
} appl_ex;

/* a struct type to define a FIFO that stores the id of unexpanded nodes*/
typedef struct {
    int array[500000];
    int read_idx;
    int write_idx;
    int empty;
    int full;
} fifo;

/* a struct type to define a variable storing the hash value of a quality or topology and its ID for a given node */
typedef struct {
    int hashNum;
    int ID;
} qtUnit;


void merge(unsigned int arr[], int l, int m, int r, unsigned int *temp)
{
    int i, j, k;
    int n1 = m - l + 1;
    int n2 =  r - m;
 
    unsigned int *L = &temp[0];
    unsigned int *R = &temp[n1];
 
    for (i = 0; i < n1; i++)
        L[i] = arr[(l + i)];
    for (j = 0; j < n2; j++)
        R[j] = arr[(m + 1+ j)];
 
    i = 0;
    j = 0;
    k = l;
    while (i < n1 && j < n2)
    {
        if (L[i] <= R[j])
        {
            arr[k] = L[i];
            i++;
        }
        else
        {
            arr[k] = R[j];
            j++;
        }
        k++;
    }
 
    while (i < n1)
    {
        arr[k] = L[i];
        i++;
        k++;
    }
 
    while (j < n2)
    {
        arr[k] = R[j];
        j++;
        k++;
    }
}

int min(int x, int y) { return (x<y)? x :y; }
 
/*merge sort function to sort quality entries or topology entries of a given node*/
void mergeSort(unsigned int arr[], int low, int high)
{
   int n = high - low + 1;
   unsigned int temp[n];
   int curr_size;  
   int left_start; 
   for (curr_size=1; curr_size<=n-1; curr_size = 2*curr_size)
   {
       for (left_start=0; left_start<n-1; left_start += 2*curr_size)
       {
           int mid = min(left_start + curr_size - 1, n-1); 
           int right_end = min(left_start + 2*curr_size - 1, n-1); 
           merge(arr, left_start, mid, right_end, temp);
       }
   }
}

/*crc64 table: used to encode a given node to a 64-bit unsigned int*/
static const unsigned long crc64_table[256] = {
0x0, 0x42f0e1eba9ea3693, 0x85e1c3d753d46d26, 0xc711223cfa3e5bb5,
0x493366450e42ecdf, 0xbc387aea7a8da4c, 0xccd2a5925d9681f9, 0x8e224479f47cb76a,
0x9266cc8a1c85d9be, 0xd0962d61b56fef2d, 0x17870f5d4f51b498, 0x5577eeb6e6bb820b,
0xdb55aacf12c73561, 0x99a54b24bb2d03f2, 0x5eb4691841135847, 0x1c4488f3e8f96ed4,
0x663d78ff90e185ef, 0x24cd9914390bb37c, 0xe3dcbb28c335e8c9, 0xa12c5ac36adfde5a,
0x2f0e1eba9ea36930, 0x6dfeff5137495fa3, 0xaaefdd6dcd770416, 0xe81f3c86649d3285,
0xf45bb4758c645c51, 0xb6ab559e258e6ac2, 0x71ba77a2dfb03177, 0x334a9649765a07e4,
0xbd68d2308226b08e, 0xff9833db2bcc861d, 0x388911e7d1f2dda8, 0x7a79f00c7818eb3b,
0xcc7af1ff21c30bde, 0x8e8a101488293d4d, 0x499b3228721766f8, 0xb6bd3c3dbfd506b,
0x854997ba2f81e701, 0xc7b97651866bd192, 0xa8546d7c558a27, 0x4258b586d5bfbcb4,
0x5e1c3d753d46d260, 0x1cecdc9e94ace4f3, 0xdbfdfea26e92bf46, 0x990d1f49c77889d5,
0x172f5b3033043ebf, 0x55dfbadb9aee082c, 0x92ce98e760d05399, 0xd03e790cc93a650a,
0xaa478900b1228e31, 0xe8b768eb18c8b8a2, 0x2fa64ad7e2f6e317, 0x6d56ab3c4b1cd584,
0xe374ef45bf6062ee, 0xa1840eae168a547d, 0x66952c92ecb40fc8, 0x2465cd79455e395b,
0x3821458aada7578f, 0x7ad1a461044d611c, 0xbdc0865dfe733aa9, 0xff3067b657990c3a,
0x711223cfa3e5bb50, 0x33e2c2240a0f8dc3, 0xf4f3e018f031d676, 0xb60301f359dbe0e5,
0xda050215ea6c212f, 0x98f5e3fe438617bc, 0x5fe4c1c2b9b84c09, 0x1d14202910527a9a,
0x93366450e42ecdf0, 0xd1c685bb4dc4fb63, 0x16d7a787b7faa0d6, 0x5427466c1e109645,
0x4863ce9ff6e9f891, 0xa932f745f03ce02, 0xcd820d48a53d95b7, 0x8f72eca30cd7a324,
0x150a8daf8ab144e, 0x43a04931514122dd, 0x84b16b0dab7f7968, 0xc6418ae602954ffb,
0xbc387aea7a8da4c0, 0xfec89b01d3679253, 0x39d9b93d2959c9e6, 0x7b2958d680b3ff75,
0xf50b1caf74cf481f, 0xb7fbfd44dd257e8c, 0x70eadf78271b2539, 0x321a3e938ef113aa,
0x2e5eb66066087d7e, 0x6cae578bcfe24bed, 0xabbf75b735dc1058, 0xe94f945c9c3626cb,
0x676dd025684a91a1, 0x259d31cec1a0a732, 0xe28c13f23b9efc87, 0xa07cf2199274ca14,
0x167ff3eacbaf2af1, 0x548f120162451c62, 0x939e303d987b47d7, 0xd16ed1d631917144,
0x5f4c95afc5edc62e, 0x1dbc74446c07f0bd, 0xdaad56789639ab08, 0x985db7933fd39d9b,
0x84193f60d72af34f, 0xc6e9de8b7ec0c5dc, 0x1f8fcb784fe9e69, 0x43081d5c2d14a8fa,
0xcd2a5925d9681f90, 0x8fdab8ce70822903, 0x48cb9af28abc72b6, 0xa3b7b1923564425,
0x70428b155b4eaf1e, 0x32b26afef2a4998d, 0xf5a348c2089ac238, 0xb753a929a170f4ab,
0x3971ed50550c43c1, 0x7b810cbbfce67552, 0xbc902e8706d82ee7, 0xfe60cf6caf321874,
0xe224479f47cb76a0, 0xa0d4a674ee214033, 0x67c58448141f1b86, 0x253565a3bdf52d15,
0xab1721da49899a7f, 0xe9e7c031e063acec, 0x2ef6e20d1a5df759, 0x6c0603e6b3b7c1ca,
0xf6fae5c07d3274cd, 0xb40a042bd4d8425e, 0x731b26172ee619eb, 0x31ebc7fc870c2f78,
0xbfc9838573709812, 0xfd39626eda9aae81, 0x3a28405220a4f534, 0x78d8a1b9894ec3a7,
0x649c294a61b7ad73, 0x266cc8a1c85d9be0, 0xe17dea9d3263c055, 0xa38d0b769b89f6c6,
0x2daf4f0f6ff541ac, 0x6f5faee4c61f773f, 0xa84e8cd83c212c8a, 0xeabe6d3395cb1a19,
0x90c79d3fedd3f122, 0xd2377cd44439c7b1, 0x15265ee8be079c04, 0x57d6bf0317edaa97,
0xd9f4fb7ae3911dfd, 0x9b041a914a7b2b6e, 0x5c1538adb04570db, 0x1ee5d94619af4648,
0x2a151b5f156289c, 0x4051b05e58bc1e0f, 0x87409262a28245ba, 0xc5b073890b687329,
0x4b9237f0ff14c443, 0x962d61b56fef2d0, 0xce73f427acc0a965, 0x8c8315cc052a9ff6,
0x3a80143f5cf17f13, 0x7870f5d4f51b4980, 0xbf61d7e80f251235, 0xfd913603a6cf24a6,
0x73b3727a52b393cc, 0x31439391fb59a55f, 0xf652b1ad0167feea, 0xb4a25046a88dc879,
0xa8e6d8b54074a6ad, 0xea16395ee99e903e, 0x2d071b6213a0cb8b, 0x6ff7fa89ba4afd18,
0xe1d5bef04e364a72, 0xa3255f1be7dc7ce1, 0x64347d271de22754, 0x26c49cccb40811c7,
0x5cbd6cc0cc10fafc, 0x1e4d8d2b65facc6f, 0xd95caf179fc497da, 0x9bac4efc362ea149,
0x158e0a85c2521623, 0x577eeb6e6bb820b0, 0x906fc95291867b05, 0xd29f28b9386c4d96,
0xcedba04ad0952342, 0x8c2b41a1797f15d1, 0x4b3a639d83414e64, 0x9ca82762aab78f7,
0x87e8c60fded7cf9d, 0xc51827e4773df90e, 0x20905d88d03a2bb, 0x40f9e43324e99428,
0x2cffe7d5975e55e2, 0x6e0f063e3eb46371, 0xa91e2402c48a38c4, 0xebeec5e96d600e57,
0x65cc8190991cb93d, 0x273c607b30f68fae, 0xe02d4247cac8d41b, 0xa2dda3ac6322e288,
0xbe992b5f8bdb8c5c, 0xfc69cab42231bacf, 0x3b78e888d80fe17a, 0x7988096371e5d7e9,
0xf7aa4d1a85996083, 0xb55aacf12c735610, 0x724b8ecdd64d0da5, 0x30bb6f267fa73b36,
0x4ac29f2a07bfd00d, 0x8327ec1ae55e69e, 0xcf235cfd546bbd2b, 0x8dd3bd16fd818bb8,
0x3f1f96f09fd3cd2, 0x41011884a0170a41, 0x86103ab85a2951f4, 0xc4e0db53f3c36767,
0xd8a453a01b3a09b3, 0x9a54b24bb2d03f20, 0x5d45907748ee6495, 0x1fb5719ce1045206,
0x919735e51578e56c, 0xd367d40ebc92d3ff, 0x1476f63246ac884a, 0x568617d9ef46bed9,
0xe085162ab69d5e3c, 0xa275f7c11f7768af, 0x6564d5fde549331a, 0x279434164ca30589,
0xa9b6706fb8dfb2e3, 0xeb46918411358470, 0x2c57b3b8eb0bdfc5, 0x6ea7525342e1e956,
0x72e3daa0aa188782, 0x30133b4b03f2b111, 0xf7021977f9cceaa4, 0xb5f2f89c5026dc37,
0x3bd0bce5a45a6b5d, 0x79205d0e0db05dce, 0xbe317f32f78e067b, 0xfcc19ed95e6430e8,
0x86b86ed5267cdbd3, 0xc4488f3e8f96ed40, 0x359ad0275a8b6f5, 0x41a94ce9dc428066,
0xcf8b0890283e370c, 0x8d7be97b81d4019f, 0x4a6acb477bea5a2a, 0x89a2aacd2006cb9,
0x14dea25f3af9026d, 0x562e43b4931334fe, 0x913f6188692d6f4b, 0xd3cf8063c0c759d8,
0x5dedc41a34bbeeb2, 0x1f1d25f19d51d821, 0xd80c07cd676f8394, 0x9afce626ce85b507,
};

unsigned long xcrc64 (const unsigned char *buf, int len, unsigned long init)
{
    unsigned long crc = init;
    while (len--)
    {
        crc = (crc << 8) ^ crc64_table[((crc >> 56) ^ *buf) & 255];
        buf++;
    }
    return crc;
}

unsigned long find_crc64 (unsigned int qt, unsigned long init){
    unsigned char qt_bytes[4];
    qt_bytes[0]=(qt>>24)&255;
    qt_bytes[1]=(qt>>16)&255;
    qt_bytes[2]=(qt>>8)&255;
    qt_bytes[3]=qt&255;
    return xcrc64(qt_bytes,4,init);
}

/* encode a given node to unsigned long int using CRC-64*/
unsigned long hostEncoding(digitFactbase *fb){
    typedef union {
        struct{
            int value: 9; //LSB
            int op: 4;
            int property: 10;
            int asset_id: 9; //MSB
        } dec;
        unsigned int enc;
    } q;
    typedef union {
        struct{ 
            int dir: 4;
            int property: 10;
            int to_asset_id: 9;
            int from_asset_id: 9;
        } dec;
        unsigned int enc;           
    } t;
    
    q encQ[(*fb).numOfQualities];
    t encT[(*fb).numOfTopologies];
    unsigned int sortedQ[(*fb).numOfQualities];
    unsigned int sortedT[(*fb).numOfTopologies];
    for(int i=0;i<(*fb).numOfQualities;i++){
        encQ[i].enc=0;//must set 0 before encoding
        encQ[i].dec.asset_id=(*fb).qualities[i].asset_id;
        encQ[i].dec.property=(*fb).qualities[i].property;
        encQ[i].dec.op=(*fb).qualities[i].op;
        encQ[i].dec.value=(*fb).qualities[i].value;
        sortedQ[i]=encQ[i].enc;
    } 
    for(int i=0;i<(*fb).numOfTopologies;i++){
        encT[i].enc=0;
        encT[i].dec.from_asset_id=(*fb).topologies[i].from_asset_id;
        encT[i].dec.to_asset_id=(*fb).topologies[i].to_asset_id;
        encT[i].dec.property=(*fb).topologies[i].property;
        encT[i].dec.dir=(*fb).topologies[i].dir;
        sortedT[i]=encT[i].enc;
    }
    //sort quality and topology entries to ensure uniqueness of each node
    mergeSort(sortedQ,0,(*fb).numOfQualities-1);
    mergeSort(sortedT,0,(*fb).numOfTopologies-1);
    //encode using CRC-64
    unsigned long resCRC=0;
    for(int i=0;i<(*fb).numOfQualities;i++){
        resCRC=find_crc64(sortedQ[i],resCRC);
    }
    for(int i=0;i<(*fb).numOfTopologies;i++){
        resCRC=find_crc64(sortedT[i],resCRC);
    }
    return resCRC;      
}


unsigned int hash1(unsigned long key) 
{
    unsigned int M=20000033; 
    return (key%M); 
} 

unsigned int hash2(unsigned long key) 
{
    unsigned int R=19991003;
    return (R-(key%R)); 
} 

/*store the encoded value of a given node to a hash table: use double hashing*/
unsigned int hostHashing(unsigned long hv, hashUnit* hTable, unsigned int* ha){
    unsigned int M=20000033;
    unsigned int index=hash1(hv);
    if (hTable[index].hashNum==0)
    {
        *ha=index;
        return 0;     
    }
    else if (hTable[index].hashNum==hv)
    {
        *ha=index;
        return 1;
    }
    else
    {  
        unsigned int index2 = hash2(hv);
        int i = 1;
        while (1) 
        { 
            unsigned int newIndex = (index+i*index2)%M; 
            if (hTable[newIndex].hashNum==0) {
                *ha = newIndex;
                return 0;
            }
            else if (hTable[newIndex].hashNum==hv) {
                *ha = newIndex;
                return 1;
            } 
            i++;
        } 
    }   
}

unsigned int h1(int key) 
{
    unsigned int M=2503; 
    return (key%M); 
} 

unsigned int h2(int key) 
{
    unsigned int R=1009;
    return (R-(key%R)); 
} 

/* search in the hash table of outgoing edges of a given node: avoid duplicate edges being saved */
unsigned int search(digitEdge *ed, int *en, int* hTable, unsigned int* ha){//M=20000033, R=19991003

    typedef union {
        struct{ 
            int to: 24;
            int ex: 8;
        } dec;
        int enc;
    } pq;
    
    pq encEd;
    encEd.enc=0;//must set 0 before encoding
    encEd.dec.to=(*ed).to_node;
    encEd.dec.ex=(*ed).exploit_id;

    (*en) = encEd.enc;

    unsigned int M=2503;
    unsigned int index=h1(encEd.enc);
    if (hTable[index]==0) //a search miss
    {
        *ha=index;         
        return 0;     
    }
    else if (hTable[index]==encEd.enc) //a search hit
    {
        *ha=index;
        return 1;     
    }
    else
    {
        unsigned int index2 = h2(encEd.enc);  
        int i = 1; 
        while (1) 
        { 
            unsigned int newIndex = (index+i*index2)%M; 
            if (hTable[newIndex]==0) {
                *ha = newIndex;
                return 0;
            }
            else if (hTable[newIndex]==encEd.enc) {
                *ha = newIndex;
                return 1;
            } 
            i++;
              
        } 
    }    
}


int fifo_read(fifo* ff, int * buf){
    if((*ff).empty==1) return 0;
    (*ff).full=0;
    (*buf)=(*ff).array[(*ff).read_idx];
    (*ff).read_idx+=1;
    if((*ff).read_idx==sizeof((*ff).array)/sizeof(int)) (*ff).read_idx=0;
    if((*ff).read_idx==(*ff).write_idx) (*ff).empty=1;
    return 1;
}

int fifo_write(fifo* ff, int val){
    if((*ff).full==1) return 0;
    (*ff).empty=0;
    (*ff).array[(*ff).write_idx]=val;
    (*ff).write_idx+=1;
    if((*ff).write_idx==sizeof((*ff).array)/sizeof(int)) (*ff).write_idx=0;
    if((*ff).write_idx==(*ff).read_idx) (*ff).full=1;
    return 1;
}

void fifo_init(fifo* ff){
    (*ff).read_idx=0;
    (*ff).write_idx=0;
    (*ff).empty=1;
    (*ff).full=0;
}

int fifo_idx_read(fifo* ff, int idx, int * buf){
    if((*ff).empty==1) return 0;
    int max_idx;
    int size_ff=sizeof((*ff).array)/sizeof(int);
    if((*ff).read_idx==(*ff).write_idx){
        max_idx=size_ff;
    }
    else if((*ff).read_idx<(*ff).write_idx){
        max_idx=(*ff).write_idx-(*ff).read_idx;
    }
    else{
        max_idx=(*ff).write_idx+size_ff-(*ff).read_idx;
    }
    if(idx>=max_idx || idx<0) return 0;
    int temp=(*ff).read_idx+idx;
    if(temp>=size_ff) temp=temp-size_ff;
    (*buf) = (*ff).array[temp];
    return 1;
}

int fifo_idx_write(fifo* ff, int idx, int *val){
    if((*ff).empty==1) return 0;
    int max_idx;
    int size_ff=sizeof((*ff).array)/sizeof(int);
    if((*ff).read_idx==(*ff).write_idx){
        max_idx=size_ff;
    }
    else if((*ff).read_idx<(*ff).write_idx){
        max_idx=(*ff).write_idx-(*ff).read_idx;
    }
    else{
        max_idx=(*ff).write_idx+size_ff-(*ff).read_idx;
    }
    if(idx>=max_idx || idx<0) return 0;
    int temp=(*ff).read_idx+idx;
    if(temp>=size_ff) temp=temp-size_ff;
    (*ff).array[temp]=(*val);
    return 1;
}

int fifo_curr_size(fifo* ff){
    if((*ff).empty==1) return 0;
    int size_ff=sizeof((*ff).array)/sizeof(int);
    if((*ff).read_idx==(*ff).write_idx){
        return size_ff;
    }
    else if((*ff).read_idx<(*ff).write_idx){
        return (*ff).write_idx-(*ff).read_idx;
    }
    else{
        return (*ff).write_idx+size_ff-(*ff).read_idx;
    }    
}


int value1(int key) 
{
    int M=5003; 
    return (key%M); 
} 

int value2(int key) 
{
    int R=4903;
    return (R-(key%R)); 
}

/* check if a quality already exists in a given node's quality list (through hash table) */
/* only encode asset id and property */
int pqSearch(digitQuality *dq, qtUnit *partQ, int *id){
    typedef union {
        struct{ 
            int property: 16;
            int asset_id: 16;
        } dec;
        int enc;
    } pq;

    int M=5003; 
    pq encPQ;
    encPQ.enc=0;
    encPQ.dec.asset_id=(*dq).asset_id;
    encPQ.dec.property=(*dq).property;
    
    int index=value1(encPQ.enc);
    if (partQ[index].hashNum==encPQ.enc) 
    {
        (*id)=partQ[index].ID;
        return 1;   
    }
    else if (partQ[index].hashNum==-1)
    {
        (*id)=-1;
        return 0;
    }
    else
    {  
	int index2 = value2(encPQ.enc);  
	int j = 1; 
	while (1) 
	{ 
	    int newIndex = (index+j*index2)%M; 
	    if (partQ[newIndex].hashNum==encPQ.enc) {
                (*id)=partQ[newIndex].ID;
                return 1;
	    }
	    else if (partQ[newIndex].hashNum==-1) {
                (*id)=-1;
                return 0;
	    } 
	    j++;
	} 
    }
}

/* check if a topology already exists in a given node's topology list(through hash table) */
/* only encode from and to asset ids and property */
int ptSearch(digitTopology *dt, qtUnit *partT, int *id){
    typedef union {
        struct{
            int property: 10;
            int to_asset_id: 11;
            int from_asset_id: 11;
        } dec;
        int enc;           
    } pt;
    int M=5003; 
    pt encPT;
    encPT.enc=0;
    encPT.dec.from_asset_id=(*dt).from_asset_id;
    encPT.dec.to_asset_id=(*dt).to_asset_id;
    encPT.dec.property=(*dt).property;

    int index=value1(encPT.enc);
    if (partT[index].hashNum==encPT.enc) 
    {
        (*id)=partT[index].ID;
        return 1;   
    }
    else if (partT[index].hashNum==-1) 
    {
        (*id)=-1;
        return 0;
    }
    else 
    {  
	int index2 = value2(encPT.enc);  
	int j = 1; 
	while (1) 
	{
	    int newIndex = (index+j*index2)%M; 
	    if (partT[newIndex].hashNum==encPT.enc) {
                (*id)=partT[newIndex].ID;
                return 1;
	    }
	    else if (partT[newIndex].hashNum==-1) {
                (*id)=-1;
                return 0;
	    } 
	    j++;  
	} 
    }
}

/* check if a quality already exists in a given node's quality list(through hash table) */
/* encode the whole entry */
int cqSearch(digitQuality *dq, qtUnit *compQ, int *id){
    typedef union {
        struct{ 
            int value: 9;
            int op: 3;
            int property: 10;
            int asset_id: 10;
        } dec;
        int enc;
    } cq;
    int M=5003; 
 
    cq encCQ;
    encCQ.enc=0;
    encCQ.dec.asset_id=(*dq).asset_id;
    encCQ.dec.property=(*dq).property;
    encCQ.dec.op=(*dq).op;
    encCQ.dec.value=(*dq).value;

    int index=value1(encCQ.enc);
    if (compQ[index].hashNum==encCQ.enc) 
    {
        (*id)=compQ[index].ID;
        return 1;   
    }
    else if (compQ[index].hashNum==-1) 
    {
        (*id)=-1;
        return 0;
    }
    else 
    {  
	int index2 = value2(encCQ.enc);  
	int j = 1; 
	while (1) 
	{ 
	    int newIndex = (index+j*index2)%M; 
	    if (compQ[newIndex].hashNum==encCQ.enc) {
                (*id)=compQ[newIndex].ID;
                return 1;
	    }
	    else if (compQ[newIndex].hashNum==-1) {
                (*id)=-1;
                return 0;
	    } 
	    j++;
	} 
    }
}

/* check if a topology already exists in a given node's topology list(through hash table) */
/* encode the whole entry */
int ctSearch(digitTopology *dt, qtUnit *compT, int *id){
    typedef union {
        struct{
            int dir: 3;
            int property: 9;
            int to_asset_id: 10;
            int from_asset_id: 10;
        } dec;
        int enc;           
    } ct;
    int M=5003; 

    ct encCT;
    encCT.enc=0;
    encCT.dec.from_asset_id=(*dt).from_asset_id;
    encCT.dec.to_asset_id=(*dt).to_asset_id;
    encCT.dec.property=(*dt).property;
    encCT.dec.dir=(*dt).dir;

    int index=value1(encCT.enc);
    if (compT[index].hashNum==encCT.enc) 
    {
        (*id)=compT[index].ID;
        return 1;   
    }
    else if (compT[index].hashNum==-1) 
    {
        (*id)=-1;
        return 0;
    }
    else 
    {  
	int index2 = value2(encCT.enc);  
	int j = 1; 
	while (1) 
	{  
	    int newIndex = (index+j*index2)%M; 
	    if (compT[newIndex].hashNum==encCT.enc) {
                (*id)=compT[newIndex].ID;
                return 1;
	    }
	    else if (compT[newIndex].hashNum==-1) {
                (*id)=-1;
                return 0;
	    } 
	    j++;  
	} 
    }
}

/*encode a given node's quality and topology entries and store the encoded values to hash tables*/
/*avoid duplicate entries*/
void qtHashing(digitFactbase *fb, qtUnit *partQ, qtUnit *partT, qtUnit *compQ, qtUnit *compT){
    typedef union {
        struct{ 
            int property: 16;
            int asset_id: 16;
        } dec;
        int enc;
    } pq;
    typedef union {
        struct{
            int property: 10;
            int to_asset_id: 11;
            int from_asset_id: 11;
        } dec;
        int enc;           
    } pt;
    typedef union {
        struct{ 
            int value: 9;
            int op: 3;
            int property: 10;
            int asset_id: 10;
        } dec;
        int enc;
    } cq;
    typedef union {
        struct{
            int dir: 3;
            int property: 9;
            int to_asset_id: 10;
            int from_asset_id: 10;
        } dec;
        int enc;           
    } ct;

    pq encPQ[(*fb).numOfQualities];
    pt encPT[(*fb).numOfTopologies];
    cq encCQ[(*fb).numOfQualities];
    ct encCT[(*fb).numOfTopologies];

    for(int i=0;i<(*fb).numOfQualities;i++){
        encCQ[i].enc=0;
        encCQ[i].dec.asset_id=(*fb).qualities[i].asset_id;
        encCQ[i].dec.property=(*fb).qualities[i].property;
        encCQ[i].dec.op=(*fb).qualities[i].op;
        encCQ[i].dec.value=(*fb).qualities[i].value;
        encPQ[i].enc=0;
        encPQ[i].dec.asset_id=(*fb).qualities[i].asset_id;
	encPQ[i].dec.property=(*fb).qualities[i].property;
    } 
    for(int i=0;i<(*fb).numOfTopologies;i++){
        encCT[i].enc=0;
        encCT[i].dec.from_asset_id=(*fb).topologies[i].from_asset_id;
        encCT[i].dec.to_asset_id=(*fb).topologies[i].to_asset_id;
        encCT[i].dec.property=(*fb).topologies[i].property;
        encCT[i].dec.dir=(*fb).topologies[i].dir;
        encPT[i].enc=0;
        encPT[i].dec.from_asset_id=(*fb).topologies[i].from_asset_id;
        encPT[i].dec.to_asset_id=(*fb).topologies[i].to_asset_id;
        encPT[i].dec.property=(*fb).topologies[i].property;
    }

    int M=5003;

    //hashing quality entries, fully encoded
    for(int i=0;i<(*fb).numOfQualities;i++){
	int index=value1(encCQ[i].enc);
	if (compQ[index].hashNum==-1) 
	{
            compQ[index].hashNum=encCQ[i].enc;
            compQ[index].ID=i;   
	}
	else 
	{  
	    int index2 = value2(encCQ[i].enc);  
	    int j = 1; 
	    while (1) 
	    { 
		 
		int newIndex = (index+j*index2)%M;  
		if (compQ[newIndex].hashNum==-1) {
                    compQ[newIndex].hashNum=encCQ[i].enc;
                    compQ[newIndex].ID=i;
                    break;
		} 
		j++;  
	    } 
	}
    }
 
    //hashing quality entries, partially encoded
    for(int i=0;i<(*fb).numOfQualities;i++){
	int index=value1(encPQ[i].enc);
	if (partQ[index].hashNum==-1) 
	{
            partQ[index].hashNum=encPQ[i].enc;
            partQ[index].ID=i;   
	}
	else 
	{  
	    int index2 = value2(encPQ[i].enc);  
	    int j = 1; 
	    while (1) 
	    { 
		int newIndex = (index+j*index2)%M; 
		if (partQ[newIndex].hashNum==-1) {
                    partQ[newIndex].hashNum=encPQ[i].enc;
                    partQ[newIndex].ID=i;
                    break;
		} 
		j++;  
	    } 
	}
    } 

    //hashing topology entries, fully encoded
    for(int i=0;i<(*fb).numOfTopologies;i++){
	int index=value1(encCT[i].enc);
	if (compT[index].hashNum==-1)
        {
            compT[index].hashNum=encCT[i].enc;
            compT[index].ID=i;   
	}
	else 	
        {  
	    int index2 = value2(encCT[i].enc);  
	    int j = 1; 
	    while (1) 
	    { 
		int newIndex = (index+j*index2)%M;  
		if (compT[newIndex].hashNum==-1) {
                    compT[newIndex].hashNum=encCT[i].enc;
                    compT[newIndex].ID=i;
                    break;
		} 
		j++;  
	    } 
	}
    }
 
    //hashing topology entries, partially encoded
    for(int i=0;i<(*fb).numOfTopologies;i++){
	int index=value1(encPT[i].enc);
	if (partT[index].hashNum==-1) 
	{
            partT[index].hashNum=encPT[i].enc;
            partT[index].ID=i;   
	}
	else 
	{  
	    int index2 = value2(encPT[i].enc);  
	    int j = 1; 
	    while (1) 
	    { 
		int newIndex = (index+j*index2)%M; 
		if (partT[newIndex].hashNum==-1) {                    
                    partT[newIndex].hashNum=encPT[i].enc;
                    partT[newIndex].ID=i;
                    break;
		} 
		j++;
	    } 
	}
    }   
}

/*Parallel AG generator function*/
/*OpenMP based*/
void parallel_gen(fifo *initDigitFrontier, AGGenDigitInstance *digitInstance, hashUnit *hashTable, int *perm1, int *perm2, int *perm3, int as, int as_sq, int as_cu, int numThrd, omp_lock_t *lock, int *numExpansions, omp_lock_t *lock2, double* threadTime, omp_lock_t *threadLocks, fifo *dFrontier){

    #pragma omp parallel num_threads(numThrd) default(none) shared(initDigitFrontier, digitInstance, hashTable, perm1, perm2, perm3, as, as_sq, as_cu, numThrd, lock, numExpansions, lock2, threadTime, threadLocks, dFrontier)
    {//parallel execution starts here
    int threadID = omp_get_thread_num();
    qtUnit q_hashTable[5003];
    qtUnit t_hashTable[5003]; 
    qtUnit qhT[5003];
    qtUnit thT[5003];
    int hT[2503];
    digitFactbase current_factbase;
    unsigned long current_hv;
    appl_ex ae[2000];
    int cand_perms[4000];
    fifo *digitFrontier = &dFrontier[threadID]; //local frontier address
    fifo_init(digitFrontier); //initialize local frontier: set it empty
    for(int fcnt=threadID; fcnt<fifo_curr_size(initDigitFrontier); fcnt+=numThrd){//fetch some nodes from main thread's frontier and store in local frontier
        int initID;
        int res22 = fifo_idx_read(initDigitFrontier,fcnt, &initID); 
        if(res22 == 0) printf("warning\n");
        omp_set_lock(&(threadLocks[threadID]));
        fifo_write(digitFrontier, initID);
        omp_unset_lock(&(threadLocks[threadID])); 
    }
    
    int cb_id;
    const int minS = 10;
    const int half = 5;

    expanding_loop: //every loop expands a node from the local frontier
        omp_set_lock(&(threadLocks[threadID]));
        fifo_read(digitFrontier, &cb_id);
        omp_unset_lock(&(threadLocks[threadID])); 
	current_factbase=(*digitInstance).factbases[cb_id]; //current node being expanded
        current_hv=(*digitInstance).factbase_hashes[current_factbase.id]; //current node's encoding value        
        numExpansions[threadID]++; //increment the number of nodes being expanded by this thread
        if(current_factbase.id%5000==0) printf("Thread %d is expanding node %d\n", threadID, current_factbase.id);

        for(int i=0;i<5003;i++){            
            q_hashTable[i].hashNum=-1;
            t_hashTable[i].hashNum=-1;
            qhT[i].hashNum=-1;
            thT[i].hashNum=-1;
        }
        for(int i=0;i<2503;i++){
            hT[i]=0;
	}
        qtHashing(&current_factbase,q_hashTable,t_hashTable,qhT,thT);

        int num_ae=0; //count the number of valid bindings
        for(int i=0; i<(*digitInstance).numOfExploits; i++) {//for-loop over exploits
            digitExploit *e = &((*digitInstance).exploits[i]);
            int num_params=(*e).num_params;
            int *perms;
            int num_ag;
            if(num_params==1){
                perms=perm1;
                num_ag=as;
	    }
            else if(num_params==2){
                perms=perm2;
                num_ag=as_sq;
            }
            else{
                perms=perm3;
                num_ag=as_cu;
            }
            if(num_params==1){//if exploit is local
                digitAssetGroup ag; 
                for(int j=0;j<num_ag;j++){//for-loop over assets: bind an asset with the current exploit
                ag.numOfQualities=(*e).num_preQ;
                ag.numOfTopologies=(*e).num_preT;
                for(int k=0;k<(*e).num_preQ;k++){//check if precondition qualities are satisfied
                    ag.hypothetical_qualities[k].asset_id=perms[j*num_params+(*e).preQ[k].param1];
                    ag.hypothetical_qualities[k].property=(*e).preQ[k].property;
                    ag.hypothetical_qualities[k].op=(*e).preQ[k].op;
                    ag.hypothetical_qualities[k].value=(*e).preQ[k].value;
                    if((*e).preQ[k].type==0){ //discrete precondition quality
		        int id1;
                        if (cqSearch(&(ag.hypothetical_qualities[k]), qhT, &id1)==0) goto to_break3;
                    }
                    else{ //continuous precondition quality
		        int id1;
                        if (pqSearch(&(ag.hypothetical_qualities[k]), q_hashTable, &id1)==0) goto to_break3;
                        switch((*e).preQ[k].op){ //four cases to compare continuous values
                            case 1: // >
                                if(current_factbase.qualities[id1].fvalue<=(*e).preQ[k].fvalue) goto to_break3;
                                break;
                            case 2: // >=
                                if(current_factbase.qualities[id1].fvalue<(*e).preQ[k].fvalue) goto to_break3;
                                break;
                            case 3: // <
                                if(current_factbase.qualities[id1].fvalue>=(*e).preQ[k].fvalue) goto to_break3;
                                break;
                            case 4: // <=
                                if(current_factbase.qualities[id1].fvalue>(*e).preQ[k].fvalue) goto to_break3;
                                break;
                            default:
                                goto to_break3;
                        }                                 
                    }
                }
                //store a valid binding
                ag.numOfParams=num_params;
                for(int k=0;k<num_params;k++){
                    ag.perm[k]=perms[j*num_params+k];
                }
                ae[num_ae].ex_id=i;
                ae[num_ae].num_params=num_params;
                for(int k=0;k<num_params;k++) {
                    ae[num_ae].perm[k]=ag.perm[k];
                }
                num_ae++;
                to_break3:;                     
                }//for-loop to output all ags with hypothetical q and t and check if they are valid
            }//end if exploit is local

            else{//if exploit is remote: two assets involved
                int q1_ae[(*digitInstance).numOfAssets];
                int q2_ae[(*digitInstance).numOfAssets];
                int no_ae1=1;
                digitAssetGroup ag;
                for(int j=0; j<(*digitInstance).numOfAssets; j++){//for-loop over assets: filter out assets not meeting the first precondition quality
                    q1_ae[j]=0;
                    ag.hypothetical_qualities[0].asset_id=j;
                    ag.hypothetical_qualities[0].property=(*e).preQ[0].property;
                    ag.hypothetical_qualities[0].op=(*e).preQ[0].op;
                    ag.hypothetical_qualities[0].value=(*e).preQ[0].value;
                    if((*e).preQ[0].type==0){ //a discrete precondition quality
		        int id1;
                        if (cqSearch(&(ag.hypothetical_qualities[0]), qhT, &id1)==1){
                            q1_ae[j]=1;
                            no_ae1=0;   
                        }
                    }
                    else{ //a continuous precondition quality
		        int id1;
                        if (pqSearch(&(ag.hypothetical_qualities[0]), q_hashTable, &id1)==1){
                            switch((*e).preQ[0].op){
                            case 1: // >
                                if(current_factbase.qualities[id1].fvalue>(*e).preQ[0].fvalue){
                                    q1_ae[j]=1;
                                    no_ae1=0;
                                }
                                break;
                            case 2: // >=
                                if(current_factbase.qualities[id1].fvalue>=(*e).preQ[0].fvalue){
                                    q1_ae[j]=1;
                                    no_ae1=0;
                                }
                                break;
                            case 3: // <
                                if(current_factbase.qualities[id1].fvalue<(*e).preQ[0].fvalue){
                                    q1_ae[j]=1;
                                    no_ae1=0;
                                }
                                break;
                            case 4: // <=
                                if(current_factbase.qualities[id1].fvalue<=(*e).preQ[0].fvalue){
                                    q1_ae[j]=1;
                                    no_ae1=0;
                                }
                                break;
                            default:
                                break;
                            }
                        }
                     }
                }//end for-loop over assets: filter out assets not meeting the first precondition quality
                if(no_ae1==1) continue; //no assets meet the first precondition quality, this exploit cannot bind successfully
                no_ae1=1;

                for(int j=0; j<(*digitInstance).numOfAssets; j++){//for-loop over assets: filter out assets not meeting the second precondition quality
                    q2_ae[j]=0;
                    ag.hypothetical_qualities[0].asset_id=j;
                    ag.hypothetical_qualities[0].property=(*e).preQ[1].property;
                    ag.hypothetical_qualities[0].op=(*e).preQ[1].op;
                    ag.hypothetical_qualities[0].value=(*e).preQ[1].value;
                    if((*e).preQ[1].type==0){ 
		        int id1;
                        if (cqSearch(&(ag.hypothetical_qualities[0]), qhT, &id1)==1){
                            q2_ae[j]=1;
                            no_ae1=0;   
                        }
                    }
                    else{ 
		        int id1;
                        if (pqSearch(&(ag.hypothetical_qualities[0]), q_hashTable, &id1)==1){
                            switch((*e).preQ[1].op){
                            case 1: // >
                                if(current_factbase.qualities[id1].fvalue>(*e).preQ[1].fvalue){
                                    q2_ae[j]=1;
                                    no_ae1=0;
                                }
                                break;
                            case 2: // >=
                                if(current_factbase.qualities[id1].fvalue>=(*e).preQ[1].fvalue){
                                    q2_ae[j]=1;
                                    no_ae1=0;
                                }
                                break;
                            case 3: // <
                                if(current_factbase.qualities[id1].fvalue<(*e).preQ[1].fvalue){
                                    q2_ae[j]=1;
                                    no_ae1=0;
                                }
                                break;
                            case 4: // <=
                                if(current_factbase.qualities[id1].fvalue<=(*e).preQ[1].fvalue){
                                    q2_ae[j]=1;
                                    no_ae1=0;
                                }
                                break;
                            default:
                                break;
                            }
                        }                                 
                    }
                }//end for-loop over assets: filter out assets not meeting the second precondition quality
                if(no_ae1==1) continue;
                
                //store candidate bindings
                int perm_cnt=0;
                for(int j=0; j<(*digitInstance).numOfAssets; j++){
                    if(q1_ae[j]==1){
                        for(int k=0; k<(*digitInstance).numOfAssets; k++){
                            if(q2_ae[k]==1){
                                cand_perms[2*perm_cnt+(*e).preQ[0].param1]=j;
                                cand_perms[2*perm_cnt+(*e).preQ[1].param1]=k;
                                perm_cnt++;
                            } 
                        }
                    }
                }                
                
                for(int j=0;j<perm_cnt;j++){//for-loop over candidate bindings
                ag.numOfQualities=(*e).num_preQ;
                ag.numOfTopologies=(*e).num_preT;
                for(int k=2;k<(*e).num_preQ;k++){//check if the remaining precondition qualities of the current candidate binding are met by the current node 
                    ag.hypothetical_qualities[k].asset_id=cand_perms[j*num_params+(*e).preQ[k].param1];
                    ag.hypothetical_qualities[k].property=(*e).preQ[k].property;
                    ag.hypothetical_qualities[k].op=(*e).preQ[k].op;
                    ag.hypothetical_qualities[k].value=(*e).preQ[k].value;
                    if((*e).preQ[k].type==0){ 
		        int id1;
                        if (cqSearch(&(ag.hypothetical_qualities[k]), qhT, &id1)==0) goto to_break;
                    }
                    else{ 
		        int id1;
                        if (pqSearch(&(ag.hypothetical_qualities[k]), q_hashTable, &id1)==0) goto to_break;
                        switch((*e).preQ[k].op){
                            case 1: // >
                                if(current_factbase.qualities[id1].fvalue<=(*e).preQ[k].fvalue) goto to_break;
                                break;
                            case 2: // >=
                                if(current_factbase.qualities[id1].fvalue<(*e).preQ[k].fvalue) goto to_break;
                                break;
                            case 3: // <
                                if(current_factbase.qualities[id1].fvalue>=(*e).preQ[k].fvalue) goto to_break;
                                break;
                            case 4: // <=
                                if(current_factbase.qualities[id1].fvalue>(*e).preQ[k].fvalue) goto to_break;
                                break;
                            default:
                                goto to_break;
                        }                                 
                    }                               
                }
 
                for(int k=0;k<(*e).num_preT;k++){//check if the precondition topologies of the current candidate binding are met by the current node
                    ag.hypothetical_topologies[k].from_asset_id=cand_perms[j*num_params+(*e).preT[k].param1];
                    ag.hypothetical_topologies[k].to_asset_id=cand_perms[j*num_params+(*e).preT[k].param2];
                    ag.hypothetical_topologies[k].property=(*e).preT[k].property;
                    ag.hypothetical_topologies[k].dir=(*e).preT[k].dir;
                    int id1;
                    //note: all three topology directions <->, -> and <- are considered
                    if (ctSearch(&(ag.hypothetical_topologies[k]), thT, &id1)==1) continue;                    
                    if ((*e).preT[k].dir==0){
                        ag.hypothetical_topologies[k].dir=1;
                        ag.hypothetical_topologies[k].from_asset_id=cand_perms[j*num_params+(*e).preT[k].param2];
                        ag.hypothetical_topologies[k].to_asset_id=cand_perms[j*num_params+(*e).preT[k].param1];
                        if (ctSearch(&(ag.hypothetical_topologies[k]), thT, &id1)==1) continue;                             
                        ag.hypothetical_topologies[k].dir=2;
                        ag.hypothetical_topologies[k].from_asset_id=cand_perms[j*num_params+(*e).preT[k].param1];
                        ag.hypothetical_topologies[k].to_asset_id=cand_perms[j*num_params+(*e).preT[k].param2];
                        if (ctSearch(&(ag.hypothetical_topologies[k]), thT, &id1)==1) continue;                             
                        ag.hypothetical_topologies[k].from_asset_id=cand_perms[j*num_params+(*e).preT[k].param2];
                        ag.hypothetical_topologies[k].to_asset_id=cand_perms[j*num_params+(*e).preT[k].param1];
                        if (ctSearch(&(ag.hypothetical_topologies[k]), thT, &id1)==1) continue;
                        goto to_break;                             
                    }
                    else if((*e).preT[k].dir==1){
                        ag.hypothetical_topologies[k].dir=0;
                        ag.hypothetical_topologies[k].from_asset_id=cand_perms[j*num_params+(*e).preT[k].param2];
                        ag.hypothetical_topologies[k].to_asset_id=cand_perms[j*num_params+(*e).preT[k].param1];
                        if (ctSearch(&(ag.hypothetical_topologies[k]), thT, &id1)==1) continue;                             
                        ag.hypothetical_topologies[k].dir=2;
                        ag.hypothetical_topologies[k].from_asset_id=cand_perms[j*num_params+(*e).preT[k].param1];
                        ag.hypothetical_topologies[k].to_asset_id=cand_perms[j*num_params+(*e).preT[k].param2];
                        if (ctSearch(&(ag.hypothetical_topologies[k]), thT, &id1)==1) continue;                             
                        ag.hypothetical_topologies[k].from_asset_id=cand_perms[j*num_params+(*e).preT[k].param2];
                        ag.hypothetical_topologies[k].to_asset_id=cand_perms[j*num_params+(*e).preT[k].param1];
                        if (ctSearch(&(ag.hypothetical_topologies[k]), thT, &id1)==1) continue;
                        goto to_break;                             
                    }
                     else{ 
                        ag.hypothetical_topologies[k].from_asset_id=cand_perms[j*num_params+(*e).preT[k].param2];
                        ag.hypothetical_topologies[k].to_asset_id=cand_perms[j*num_params+(*e).preT[k].param1];
                        if (ctSearch(&(ag.hypothetical_topologies[k]), thT, &id1)==1) continue;
                        goto to_break;                             
                    }
                }
                
                //store a valid binding 
                ag.numOfParams=num_params;
                for(int k=0;k<num_params;k++){
                    ag.perm[k]=cand_perms[j*num_params+k];
                }
                ae[num_ae].ex_id=i;
                ae[num_ae].num_params=num_params;
                for(int k=0;k<num_params;k++) {
                    ae[num_ae].perm[k]=ag.perm[k];
                }
                num_ae++;
                to_break:;                     
                } //end for-loop over candidate bindings
            }//end if exploit is remote                              
        }//end for-loop over exploits

        for(int i=0; i<num_ae; i++) {//for-loop over valid bindings to discover neighbors and outgoing edges for the current node  
            digitExploit ex=(*digitInstance).exploits[ae[i].ex_id];
            int num_postQ=ex.num_postQ;
            int num_postT=ex.num_postT;
            digitFactbase new_factbase=current_factbase;//make a copy of the current node
            int del_Q=0;
            int del_T=0;
            for(int j=0;j<num_postQ;j++){ //process postcondition qualities of the current valid binding: perform insert/update/delete on the copy of the current node and obtain a possibly new node
                int act=ex.postQ[j].action;
                digitQuality tempQ;
                tempQ.asset_id=ae[i].perm[ex.postQ[j].param1];
                tempQ.property=ex.postQ[j].property;
                tempQ.op=ex.postQ[j].op;
                tempQ.value=ex.postQ[j].value;
                tempQ.fvalue=ex.postQ[j].fvalue;
		int id1,id2;
                switch(act){ 
                    case 0: //insert a new quality to the copy node's quality list
                        if(pqSearch(&tempQ,q_hashTable,&id1)==0){
                            new_factbase.qualities[new_factbase.numOfQualities]=tempQ;
                            new_factbase.numOfQualities++;
                        }
                        else if(cqSearch(&tempQ,qhT,&id2)==0){
                            new_factbase.qualities[id1].op=tempQ.op;
                            new_factbase.qualities[id1].value=tempQ.value;
                            new_factbase.qualities[id1].fvalue=tempQ.fvalue;
                        } 
                        break;
                    case 1: //update a quality of the copy node
                        if(pqSearch(&tempQ,q_hashTable,&id1)==1){
                            new_factbase.qualities[id1].op=tempQ.op;
                            new_factbase.qualities[id1].value=tempQ.value;
                            new_factbase.qualities[id1].fvalue=tempQ.fvalue;
                        }
                        else {
                            new_factbase.qualities[new_factbase.numOfQualities]=tempQ;
                            new_factbase.numOfQualities++;
                        }
                        break;                        
                    case 2: //delete a quality from the copy node
                        if(pqSearch(&tempQ,q_hashTable,&id1)==1){
                            new_factbase.qualities[id1].asset_id=-1;  
                            del_Q++;//count how many qualities have been deleted from the copy node  
                        }
                        break;
                    default:
                        break;
                }
            }// end process postcondition qualities

            for(int j=0;j<num_postT;j++){ //process postcondition topologies of the current valid binding: perform insert/update/delete on the copy of the current node and obtain a possibly new node
                int act=ex.postT[j].action;
                digitTopology tempT;
                tempT.from_asset_id=ae[i].perm[ex.postT[j].param1];
                tempT.to_asset_id=ae[i].perm[ex.postT[j].param2];
                tempT.property=ex.postT[j].property;
                tempT.dir=ex.postT[j].dir;
		int id1,id2;
                switch(act){ 
                    case 0: //insert a new topology to the copy node
                        if(ptSearch(&tempT,t_hashTable,&id1)==0){
                            new_factbase.topologies[new_factbase.numOfTopologies]=tempT;
                            new_factbase.numOfTopologies++;
                        }
                        else if(ctSearch(&tempT,thT,&id2)==0){
                            new_factbase.topologies[id1].dir=tempT.dir;
                        } 
                        break;
                    case 1: //update a topology of the copy node
                        if(ptSearch(&tempT,t_hashTable,&id1)==1){
                            new_factbase.topologies[id1].dir=tempT.dir;
                        }
                        else {
                            new_factbase.topologies[new_factbase.numOfTopologies]=tempT;
                            new_factbase.numOfTopologies++;
                        }
                        break;                        
                    case 2: //delete a topology from the copy node
                        if(ptSearch(&tempT,t_hashTable,&id1)==1){
                            new_factbase.topologies[id1].from_asset_id=-1;  
                            del_T++; //count how many topologies have been deleted from the copy node 
                        } 
                        break;
                    default:
                        break;
                }                
            }
            
            //reorganize the quality array of the copy node if there is delete operation
            if(del_Q>0){ 
                digitFactbase temp_factbase=new_factbase;
                temp_factbase.numOfQualities=0;
                for(int j=0;j<new_factbase.numOfQualities;j++){
                    if(new_factbase.qualities[j].asset_id!=-1){ 
                        temp_factbase.qualities[temp_factbase.numOfQualities]=new_factbase.qualities[j];
                        temp_factbase.numOfQualities++;
                    }
                }
                new_factbase=temp_factbase;
            }
            //reorganize the topology aray of the copy node if there is delete operation
            if(del_T>0){ 
                digitFactbase temp_factbase=new_factbase;
                temp_factbase.numOfTopologies=0;
                for(int j=0;j<new_factbase.numOfTopologies;j++){
                    if(new_factbase.topologies[j].from_asset_id!=-1){ 
                        temp_factbase.topologies[temp_factbase.numOfTopologies]=new_factbase.topologies[j];
                        temp_factbase.numOfTopologies++;
                    }
                }
                new_factbase=temp_factbase;
            }

            //encode the copy node after processing postconditions
            unsigned long new_hv=hostEncoding(&new_factbase);
            if(new_hv == current_hv) continue; //if the copy node is identical to the current node, continue to process the next valid binding
            unsigned int new_ha;
           
            omp_set_lock(lock);//acquire the lock to access global data structures: hashtable, nodecounter
            if(hostHashing(new_hv,hashTable,&new_ha)==0) {//a search miss indicates a new node
                new_factbase.id=(*digitInstance).numOfFactbases; //assign id to the new node
                (*digitInstance).numOfFactbases++; //increment nodecounter
                hashTable[new_ha].hashNum=new_hv; //hash the new node to global hashtable
                hashTable[new_ha].factbaseID=new_factbase.id;
                omp_unset_lock(lock);//release the lock to access global data structures
                (*digitInstance).factbases[new_factbase.id]=new_factbase;
                (*digitInstance).factbase_hashes[new_factbase.id]=new_hv;
                omp_set_lock(&(threadLocks[threadID]));//acquire the lock to access local frontier
                int res2 = fifo_write(digitFrontier,new_factbase.id);
                omp_unset_lock(&(threadLocks[threadID]));//release the lock to access local frontier
                digitEdge ed;//create the edge from the current node to this new node
                ed.from_node=current_factbase.id;
                ed.to_node=new_factbase.id;
                ed.exploit_id=ae[i].ex_id;
		unsigned int ha;
		int val;
		if(search(&ed, &val, hT, &ha)==0){
                    omp_set_lock(lock2);//acquire the lock to access global edgecounter
                    ed.id=(*digitInstance).numOfEdges++;
                    omp_unset_lock(lock2);//release the lock to access global edgecounter
                    (*digitInstance).edges[ed.id]=ed;
                    hT[ha] = val;
		}		    
            }
            else{//a search hit indicates a discovered node
                omp_unset_lock(lock);
                digitEdge ed;
                ed.from_node=current_factbase.id;
                ed.to_node=hashTable[new_ha].factbaseID;
                ed.exploit_id=ae[i].ex_id;
		unsigned int ha;
		int val;
		if(search(&ed, &val, hT, &ha)==0){
                    omp_set_lock(lock2);
                    ed.id=(*digitInstance).numOfEdges++;
                    omp_unset_lock(lock2);
                    (*digitInstance).edges[ed.id]=ed;
                    hT[ha] = val;
		}		    
            }    
        }//end for-loop over valid bindings
        
        omp_set_lock(&(threadLocks[threadID]));//acquire the lock to access local frontier
        if(fifo_curr_size(digitFrontier)){//if the local frontier is not empty, continue to expand nodes from local frontier
            omp_unset_lock(&(threadLocks[threadID]));
            goto expanding_loop;
        }
        else{//if the local frontier is empty, steal node(s) from other threads' local frontiers
            omp_unset_lock(&(threadLocks[threadID]));
            int numStolen = 0;
            int idBuf[half];
            for(int m=1; m<numThrd; m++){
                omp_set_lock(&(threadLocks[(threadID+m)%numThrd]));
                if(fifo_curr_size(&dFrontier[(threadID+m)%numThrd])>=minS){
                    for(int n=0; n<half; n++){
                        fifo_read(&dFrontier[(threadID+m)%numThrd], &idBuf[n]); //pop a factbase from frontier
                    }
                    numStolen = half;         
                }
                omp_unset_lock(&(threadLocks[(threadID+m)%numThrd]));
                if(numStolen>0){
                    omp_set_lock(&(threadLocks[threadID]));
                    for(int n=0; n<numStolen; n++) fifo_write(digitFrontier, idBuf[n]);
                    omp_unset_lock(&(threadLocks[threadID]));
                    break;
                }
            }
            if(numStolen==0) goto finish; //no nodes stolen, then terminate this thread
            else{//if work-stealing successful, continue to expand nodes from local frontier
                goto expanding_loop;
            }
        }        
        finish:;

    }//parallel execution ends here
}

/* generator function: called by main function, generate the target attack graph */
void generator(AGGenDigitInstance *digitInstance) {
    printf("\n");
    printf(" ############## Attack graph generation begins ############# \n");
    printf("\n");
    printf(" --->>> Single Threaded Phase .........................\n");
    //==============step 1: process the root node
    //store the root node in the node array of the attack graph instance
    (*digitInstance).numOfFactbases=1; 
    (*digitInstance).factbases[0].id=0; 
    (*digitInstance).factbases[0].numOfQualities=(*digitInstance).numOfInitQualities;
    for(int i=0;i<(*digitInstance).factbases[0].numOfQualities;i++){
        (*digitInstance).factbases[0].qualities[i]=(*digitInstance).initial_qualities[i];
    }
    (*digitInstance).factbases[0].numOfTopologies=(*digitInstance).numOfInitTopologies;  
    for(int i=0;i<(*digitInstance).factbases[0].numOfTopologies;i++){
        (*digitInstance).factbases[0].topologies[i]=(*digitInstance).initial_topologies[i];
    }
    //create edge hash table for the main thread
    int *hT = (int *)malloc(2503*sizeof(int));
    //create node hashtable
    hashUnit *hashTable=(hashUnit *)malloc(20000033*sizeof(hashUnit));
    for(int i=0;i<20000033;i++){
        hashTable[i].hashNum=0;
    }

    struct timeval ts8,tf8;
    gettimeofday(&ts8,NULL);
    unsigned long hashValue=hostEncoding(&((*digitInstance).factbases[0])); 

    printf("--->>> hashvalue of the root node: %lu\n", hashValue);
    unsigned int *hashAddr = (unsigned int *)malloc(sizeof(unsigned int));
    if(hostHashing(hashValue,hashTable,hashAddr)==0) {
        hashTable[*hashAddr].hashNum=hashValue;
        hashTable[*hashAddr].factbaseID=(*digitInstance).factbases[0].id;
        (*digitInstance).factbase_hashes[(*digitInstance).factbases[0].id]=hashValue;  
    }
    gettimeofday(&tf8,NULL);
    double tdiff8=(tf8.tv_sec-ts8.tv_sec)*1000.0+(tf8.tv_usec-ts8.tv_usec)/1000.0;
    printf("--->>> hashAddr of the root node: %d\n", *hashAddr);
    printf("--->>> hashing the root node took %lf ms\n", tdiff8);
    (*digitInstance).numOfEdges=0;//no edge is discovered at the beginning    
    
    //===============step 2: serial expansion of the attack graph
    //define the main thread FIFO
    fifo *digitFrontier=(fifo *)malloc(sizeof(fifo));
    fifo_init(digitFrontier);
    printf("--->>> Initial size of the main thread frontier: %d\n", fifo_curr_size(digitFrontier));
    printf("--->>> Enqueuing the root node into the main thread frontier is successful? Yes(1), No(0) --- %d\n", fifo_write(digitFrontier, (*digitInstance).factbases[0].id));
    printf("--->>> The current size fo the main thread frontier: %d\n", fifo_curr_size(digitFrontier));
    //define constants and arrays: used to find valid bindings of exploits and assets 
    int as=(*digitInstance).numOfAssets;
    int as_sq=as*as;
    int as_cu=as*as*as;   
    int *perm1 = (int *)malloc(as*sizeof(int));
    int *perm2 = (int *)malloc(2*as_sq*sizeof(int));
    int *perm3 = (int *)malloc(3*as_cu*sizeof(int));
    for(int i=0;i<as;i++){
        perm1[i]=i;
    }
    for(int i=0;i<as;i++){
        for(int j=0;j<as;j++){
            perm2[(i*as+j)*2]=j;
            perm2[(i*as+j)*2+1]=i;
        }
    }
    for(int i=0;i<as;i++){
        for(int j=0;j<as;j++){
            for(int k=0;k<as;k++){
                perm3[(i*as_sq+j*as+k)*3]=k;
                perm3[(i*as_sq+j*as+k)*3+1]=j;
                perm3[(i*as_sq+j*as+k)*3+2]=i;           
            }
        }
    }
    printf("--->>> Node hashTable size in bytes: %ld\n", sizeof(hashTable[0])*20000033);
    printf("--->>> Attack graph instance size in bytes:  %ld\n", sizeof(*digitInstance));
    printf("--->>> Main thread frontier size in bytes: %ld\n", sizeof(*digitFrontier));
    printf("--->>> Current number of discovered nodes in the attack graph instance: %d\n", (*digitInstance).numOfFactbases);
    printf("--->>> Current number of nodes in the main thread frontier: %d\n", fifo_curr_size(digitFrontier));
  
    struct timeval ts10,tf10;
    gettimeofday(&ts10,NULL);//start measuring the time needed to generate the target attack graph
    //while(fifo_curr_size(digitFrontier)){
    while(fifo_curr_size(digitFrontier)<initQSize){//while-loop to fill main thread frontier with enough nodes for all the parallel threads
	int cb_id;
        digitFactbase current_factbase;
        fifo_read(digitFrontier, &cb_id);
	current_factbase=(*digitInstance).factbases[cb_id]; //dequeue a node from the main thread frontier as the current node being expanded
	unsigned long current_hv=(*digitInstance).factbase_hashes[current_factbase.id];
        //define and initialize quality and topology hash tables 
        qtUnit q_hashTable[5003];
        qtUnit t_hashTable[5003]; 
        qtUnit qhT[5003];
        qtUnit thT[5003];
        for(int i=0;i<5003;i++){
            q_hashTable[i].hashNum=-1;
            t_hashTable[i].hashNum=-1;
            qhT[i].hashNum=-1;
            thT[i].hashNum=-1;
        }
        qtHashing(&current_factbase,q_hashTable,t_hashTable,qhT,thT);
        //reset the main thread edge hash table
        for(int i=0;i<2503;i++){            
            hT[i]=0;
	}

        int num_ae=0; //define the variable to count the number of valid bindings
        appl_ex ae[2000]; //define the array to store valid bindings
        for(int i=0; i<(*digitInstance).numOfExploits; i++) {//for-loop over exploits
            digitExploit *e = &((*digitInstance).exploits[i]);
            int num_params=(*e).num_params;
            int *perms;
            int num_ag;
            if(num_params==1){
                perms=perm1;
                num_ag=as;
	    }
            else if(num_params==2){
                perms=perm2;
                num_ag=as_sq;
            }
            else{
                perms=perm3;
                num_ag=as_cu;
            }
            digitAssetGroup ag; 
            for(int j=0;j<num_ag;j++) {//for-loop over asset (local exploit) or asset pairs (remote exploits)
                ag.numOfQualities=(*e).num_preQ;
                ag.numOfTopologies=(*e).num_preT;
                for(int k=0;k<(*e).num_preQ;k++){//check if the current binding's precondition qualities are met by the current node
                    ag.hypothetical_qualities[k].asset_id=perms[j*num_params+(*e).preQ[k].param1];
                    ag.hypothetical_qualities[k].property=(*e).preQ[k].property;
                    ag.hypothetical_qualities[k].op=(*e).preQ[k].op;
                    ag.hypothetical_qualities[k].value=(*e).preQ[k].value;
                    if((*e).preQ[k].type==0){ 
		        int id1;
                        if (cqSearch(&(ag.hypothetical_qualities[k]), qhT, &id1)==0) goto to_break;
                    }
                    else{ 
		        int id1;
                        if (pqSearch(&(ag.hypothetical_qualities[k]), q_hashTable, &id1)==0) goto to_break;
                        switch((*e).preQ[k].op){
                            case 1: // >
                                if(current_factbase.qualities[id1].fvalue<=(*e).preQ[k].fvalue) goto to_break;
                                break;
                            case 2: // >=
                                if(current_factbase.qualities[id1].fvalue<(*e).preQ[k].fvalue) goto to_break;
                                break;
                            case 3: // <
                                if(current_factbase.qualities[id1].fvalue>=(*e).preQ[k].fvalue) goto to_break;
                                break;
                            case 4: // <=
                                if(current_factbase.qualities[id1].fvalue>(*e).preQ[k].fvalue) goto to_break;
                                break;
                            default:
                                goto to_break;
                        }                                 
                    }
                } 
                for(int k=0;k<(*e).num_preT;k++){//check if the current binding's precondition topologies are met by the current node
                    ag.hypothetical_topologies[k].from_asset_id=perms[j*num_params+(*e).preT[k].param1];
                    ag.hypothetical_topologies[k].to_asset_id=perms[j*num_params+(*e).preT[k].param2];
                    ag.hypothetical_topologies[k].property=(*e).preT[k].property;
                    ag.hypothetical_topologies[k].dir=(*e).preT[k].dir;
                    int id1;
                    if (ctSearch(&(ag.hypothetical_topologies[k]), thT, &id1)==1) continue;           
                    if ((*e).preT[k].dir==0){
                        ag.hypothetical_topologies[k].dir=1;
                        ag.hypothetical_topologies[k].from_asset_id=perms[j*num_params+(*e).preT[k].param2];
                        ag.hypothetical_topologies[k].to_asset_id=perms[j*num_params+(*e).preT[k].param1];
                        if (ctSearch(&(ag.hypothetical_topologies[k]), thT, &id1)==1) continue;                             
                        ag.hypothetical_topologies[k].dir=2;
                        ag.hypothetical_topologies[k].from_asset_id=perms[j*num_params+(*e).preT[k].param1];
                        ag.hypothetical_topologies[k].to_asset_id=perms[j*num_params+(*e).preT[k].param2];
                        if (ctSearch(&(ag.hypothetical_topologies[k]), thT, &id1)==1) continue;                             
                        ag.hypothetical_topologies[k].from_asset_id=perms[j*num_params+(*e).preT[k].param2];
                        ag.hypothetical_topologies[k].to_asset_id=perms[j*num_params+(*e).preT[k].param1];
                        if (ctSearch(&(ag.hypothetical_topologies[k]), thT, &id1)==1) continue;
                        goto to_break;                             
                    }
                    else if((*e).preT[k].dir==1){
                        ag.hypothetical_topologies[k].dir=0;
                        ag.hypothetical_topologies[k].from_asset_id=perms[j*num_params+(*e).preT[k].param2];
                        ag.hypothetical_topologies[k].to_asset_id=perms[j*num_params+(*e).preT[k].param1];
                        if (ctSearch(&(ag.hypothetical_topologies[k]), thT, &id1)==1) continue;                             
                        ag.hypothetical_topologies[k].dir=2;
                        ag.hypothetical_topologies[k].from_asset_id=perms[j*num_params+(*e).preT[k].param1];
                        ag.hypothetical_topologies[k].to_asset_id=perms[j*num_params+(*e).preT[k].param2];
                        if (ctSearch(&(ag.hypothetical_topologies[k]), thT, &id1)==1) continue;                             
                        ag.hypothetical_topologies[k].from_asset_id=perms[j*num_params+(*e).preT[k].param2];
                        ag.hypothetical_topologies[k].to_asset_id=perms[j*num_params+(*e).preT[k].param1];
                        if (ctSearch(&(ag.hypothetical_topologies[k]), thT, &id1)==1) continue;
                        goto to_break;                             
                    }
                    else{ 
                        ag.hypothetical_topologies[k].from_asset_id=perms[j*num_params+(*e).preT[k].param2];
                        ag.hypothetical_topologies[k].to_asset_id=perms[j*num_params+(*e).preT[k].param1];
                        if (ctSearch(&(ag.hypothetical_topologies[k]), thT, &id1)==1) continue;
                        goto to_break;                             
                    }
                }
                //store a valid binding
                ag.numOfParams=num_params;
                for(int k=0;k<num_params;k++){
                    ag.perm[k]=perms[j*num_params+k];
                }
                ae[num_ae].ex_id=i;
                ae[num_ae].num_params=num_params;
                for(int k=0;k<num_params;k++) {
                    ae[num_ae].perm[k]=ag.perm[k];
                }
                num_ae++;
                to_break:;                     
            }//end for-loop over assets or asset pairs                                 
        }//end for-loop over exploits

        for(int i=0; i<num_ae; i++) {//for-loop over valid bindings
            digitExploit ex=(*digitInstance).exploits[ae[i].ex_id];
            int num_postQ=ex.num_postQ;
            int num_postT=ex.num_postT;
            digitFactbase new_factbase=current_factbase; //make a copy node from the current node
            int del_Q=0;
            int del_T=0;
            for(int j=0;j<num_postQ;j++){ //process the postcondition qualities of the current valid binding on the copy node
                int act=ex.postQ[j].action;
                digitQuality tempQ;
                tempQ.asset_id=ae[i].perm[ex.postQ[j].param1];
                tempQ.property=ex.postQ[j].property;
                tempQ.op=ex.postQ[j].op;
                tempQ.value=ex.postQ[j].value;
                tempQ.fvalue=ex.postQ[j].fvalue;
		int id1,id2;
                switch(act){ 
                    case 0: //insert a quality into the copy node
                        if(pqSearch(&tempQ,q_hashTable,&id1)==0){
                            new_factbase.qualities[new_factbase.numOfQualities]=tempQ;
                            new_factbase.numOfQualities++;
                        }
                        else if(cqSearch(&tempQ,qhT,&id2)==0){
                            new_factbase.qualities[id1].op=tempQ.op;
                            new_factbase.qualities[id1].value=tempQ.value;
                            new_factbase.qualities[id1].fvalue=tempQ.fvalue;
                        }
                        break;
                    case 1: //update a quality of the copy node
                        if(pqSearch(&tempQ,q_hashTable,&id1)==1){
                            new_factbase.qualities[id1].op=tempQ.op;
                            new_factbase.qualities[id1].value=tempQ.value;
                            new_factbase.qualities[id1].fvalue=tempQ.fvalue;
                        }
                        else {
                            new_factbase.qualities[new_factbase.numOfQualities]=tempQ;
                            new_factbase.numOfQualities++;
                        }
                        break;                        
                    case 2: //delete a quality from the copy node
                        if(pqSearch(&tempQ,q_hashTable,&id1)==1){
                            new_factbase.qualities[id1].asset_id=-1;  
                            del_Q++;//increment the number of deleted qualities for the copy node
                        }
                        break;
                    default:
                        break;
                }            
            }
            for(int j=0;j<num_postT;j++){ //process postcondition topologies of the current valid binding on the copy node
                int act=ex.postT[j].action;
                digitTopology tempT;
                tempT.from_asset_id=ae[i].perm[ex.postT[j].param1];
                tempT.to_asset_id=ae[i].perm[ex.postT[j].param2];
                tempT.property=ex.postT[j].property;
                tempT.dir=ex.postT[j].dir;
		int id1,id2;
                switch(act){ 
                    case 0: //insert a topology into the copy node
                        if(ptSearch(&tempT,t_hashTable,&id1)==0){
                            new_factbase.topologies[new_factbase.numOfTopologies]=tempT;
                            new_factbase.numOfTopologies++;
                        }
                        else if(ctSearch(&tempT,thT,&id2)==0){
                            new_factbase.topologies[id1].dir=tempT.dir;
                        } 
                        break;
                    case 1: //update a topology of the copy node
                        if(ptSearch(&tempT,t_hashTable,&id1)==1){
                            new_factbase.topologies[id1].dir=tempT.dir;
                        }
                        else {
                            new_factbase.topologies[new_factbase.numOfTopologies]=tempT;
                            new_factbase.numOfTopologies++;
                        }
                        break;                        
                    case 2: //delete a topology from the copy node
                        if(ptSearch(&tempT,t_hashTable,&id1)==1){                            
                            new_factbase.topologies[id1].from_asset_id=-1;  
                            del_T++; //increment the number of deleted topologies of the copy node 
                        }
                        break;
                    default:
                        break;
                }                
            } 
            //reorganize the quality array of the copy node if any quality is deleted
            if(del_Q>0){ 
                digitFactbase temp_factbase=new_factbase;
                temp_factbase.numOfQualities=0;
                for(int j=0;j<new_factbase.numOfQualities;j++){
                    if(new_factbase.qualities[j].asset_id!=-1){ 
                        temp_factbase.qualities[temp_factbase.numOfQualities]=new_factbase.qualities[j];
                        temp_factbase.numOfQualities++;
                    }
                }
                new_factbase=temp_factbase;
            }
            //reorganize the topology array of the copy node if any topology is deleted
            if(del_T>0){ 
                digitFactbase temp_factbase=new_factbase;
                temp_factbase.numOfTopologies=0;
                for(int j=0;j<new_factbase.numOfTopologies;j++){
                    if(new_factbase.topologies[j].from_asset_id!=-1){ 
                        temp_factbase.topologies[temp_factbase.numOfTopologies]=new_factbase.topologies[j];
                        temp_factbase.numOfTopologies++;
                    }
                }
                new_factbase=temp_factbase;
            }

            //encode the copy node
            unsigned long new_hv=hostEncoding(&new_factbase);
            if(new_hv == current_hv) continue; //the copy node is identical to the current node, continue to check the next valid binding
            unsigned int new_ha;
            if(hostHashing(new_hv,hashTable,&new_ha)==0) {//a search miss indicates that the copy node is new node
                new_factbase.id=(*digitInstance).numOfFactbases; //assign an id to the copy node
                (*digitInstance).numOfFactbases++;//increment the number of discovered nodes kept in the attack graph instance
                (*digitInstance).factbases[new_factbase.id]=new_factbase; //store the copy node to the attack graph instance
                (*digitInstance).factbase_hashes[new_factbase.id]=new_hv; 
                hashTable[new_ha].hashNum=new_hv; //hash the copy node to the global node hashtable
                hashTable[new_ha].factbaseID=new_factbase.id;
                int res2 = fifo_write(digitFrontier,new_factbase.id);
                digitEdge ed; //create a new edge from the current node to the copy node
                ed.id=(*digitInstance).numOfEdges;
                ed.from_node=current_factbase.id;
                ed.to_node=new_factbase.id;
                ed.exploit_id=ae[i].ex_id;
		unsigned int ha;
		int val;
		if(search(&ed, &val, hT, &ha)==0){ //if this new edge is not discovered
                    (*digitInstance).edges[ed.id]=ed; //store the edge to the attack graph instance
                    (*digitInstance).numOfEdges++;
                    hT[ha] = val;
		}		    
            }
            else{//a search hit indicates that the copy node already discovered
                digitEdge ed; //create a new edge and store it
                ed.id=(*digitInstance).numOfEdges;
                ed.from_node=current_factbase.id;
                ed.to_node=hashTable[new_ha].factbaseID;
                ed.exploit_id=ae[i].ex_id;
		unsigned int ha;
		int val;
		if(search(&ed, &val, hT, &ha)==0){
                    (*digitInstance).edges[ed.id]=ed;
                    (*digitInstance).numOfEdges++;
                    hT[ha] = val;
		}		    
            }
        }// end for-loop over valid bindings
    }//end while-loop 
   
    printf("--->>> Initial expansion by the main thread is done.\n");
    printf("--->>> The preset minimum number of nodes in the main thread frontier is %d\n", initQSize);
    printf("--->>> The actual number of nodes in the main thread frontier is %d\n", fifo_curr_size(digitFrontier));
    printf("--->>> The preset number of OpenMP threads is %d\n", numThreads);
    printf("\n");

    //===============step 3: parallel expansion of the attack graph
    printf("--->>> Multi-threaded Phase ...........................\n");
    free(hT);
    int initS = fifo_curr_size(digitFrontier);
    int fbByHost = (*digitInstance).numOfFactbases; //number of nodes discovered by the main thread

    omp_lock_t *lock = (omp_lock_t *)malloc(sizeof(omp_lock_t)); //define a lock to access global data structures: node hashtable and nodecounter
    omp_lock_t *lock2 = (omp_lock_t *)malloc(sizeof(omp_lock_t)); //define a lock to access global edgecounter
    omp_init_lock(lock);
    omp_init_lock(lock2);
    omp_lock_t *threadLocks = (omp_lock_t *)malloc(numThreads*sizeof(omp_lock_t)); //define a lock for each thread's local frontier access
    for(int i=0; i<numThreads; i++) omp_init_lock(&threadLocks[i]);

    int *numExpansions = (int *)malloc(numThreads*sizeof(int)); //define variables for parallel threads to count the number of expanded nodes
    for(int i=0; i<numThreads; i++) numExpansions[i]=0;

    double *threadTime = (double *)malloc(numThreads*6*sizeof(double));
    for(int i=0; i<numThreads*6; i++) threadTime[i]=0.0;
    
    fifo *dFrontier = (fifo *)malloc(numThreads*sizeof(fifo)); //define local frontiers for parallel threads
    
    //call the parallel attack graph generator
    parallel_gen(digitFrontier, digitInstance, hashTable, perm1, perm2, perm3, as, as_sq, as_cu, numThreads, lock, numExpansions, lock2, threadTime, threadLocks, dFrontier);
   
    gettimeofday(&tf10,NULL);//end measuring the time needed to generate the target attack graph 
    double tdiff10=(tf10.tv_sec-ts10.tv_sec)+(tf10.tv_usec-ts10.tv_usec)/1000000.0;

    //===============step 4: report the results
    printf("################ The target attack graph has been generated successfully #################\n");
    printf("\n");
    printf("--->>> Number of nodes expanded by main threads:\n");
    printf("%d\n", fbByHost-initS);
    printf("--->>> Number of nodes expanded by each parallel thread:\n");
    
    for(int i=0; i<numThreads; i++){
        printf("-- Thread %d expanded %d nodes.\n", i, numExpansions[i]);
	fbByHost += numExpansions[i];
    }

    printf("\n");
    printf("--->>> The number of nodes in the attack graph is %d\n", (*digitInstance).numOfFactbases);
    printf("--->>> The number of edges in the attack graph is %d\n", (*digitInstance).numOfEdges);
    printf("--->>> The attack graph generation took %lf seconds\n", tdiff10); 
}
