typedef void UNREG _PARAMS((void *));

typedef struct _callback_meta {
        int link_count;
        void *callback_data;
        UNREG *unreg_func;
        void *unreg_data;
        struct _callback_meta *next;
} callback_meta;

extern callback_meta * callbackRegister _PARAMS((void *, UNREG *, void *, callback_meta **));
extern void *callbackCheck _PARAMS((callback_meta *cbm));
extern void callbackUnlink _PARAMS((callback_meta *cbm));
extern void callbackUnlinkList _PARAMS((callback_meta *cbm));

