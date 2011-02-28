/*
 * Implemented by a generous soul for public consumption.
 */

#include <stdio.h>  
#include <errno.h>  
#include <string.h>  
#include <stdlib.h>  

/* 
 * A portable implementation of open_memstream 
 */    

struct my_stream_data {    
	char * buffer;    	/* Pointer to buffer 	*/
	size_t buf_size;	/* Size of buffer 	*/
	size_t allocation;      /* Physical allocation 	*/
	char  **buf_ptr;        /* Pointer to pointer handed in */
	size_t *chunk;  	/* Pointer to chunk size handed in */
};    

/* 
 * This function is plugged into the funopen() table as the
 * function to be called to perform writes. It takes
 * an opaque handle, as a file descriptor, and the rest
 * is the same as the write( ) system call.
 *
 * Static, as scope is within this module only 
 */

static int 
memstream_writefn(void *cookie, const char *buffer, int bytes) 
{
		/* cookie is the opaque handle to my_stream_data */
	struct my_stream_data *mys = cookie;  
		/* New end size, after new bytes and an eof */
	size_t new_end = mys->buf_size + bytes + 1;    
		/* Nextspace is the current, and soon to be updated
 		   physical allocation size */
	size_t nextspace = mys->allocation;    
		/* new buffer is where things will land after ralloc() */
	char *newbuffer;        

	  	/* If outgrown current physical allocation */
	if(new_end > mys->allocation) {
	        while(mys->allocation < new_end)   /* get more */
		   	nextspace += 4096;         /* add a page */
		if(!(newbuffer = realloc(mys->buffer, nextspace)))        
			   return -1;      	   /* Oh no !! */
		mys->buffer = newbuffer;           /* new buffer */ 
		mys->allocation = nextspace;       /* total phys allocated */
	}    
		/* copy the new stuff to the new space */
	memcpy(mys->buffer + mys->buf_size, buffer, bytes);    
		/* move buf_size to new end of buf */
	mys->buf_size += bytes;    
	      /* zero out, as per spec for adding eof (null) to end */
	mys->buffer[mys->buf_size] = 0;  
		/* Move buffer pointer, as per spec */
	*mys->buf_ptr = mys->buffer;    
		/* Update the logical chunk size, as per spec */
	*mys->chunk = mys->buf_size;    
		/* return the bytes processed */
	return bytes;  
}    

/*
 * This function is the user visible API. It conforms to the
 * specification for open_memstream( ) as defined by POSIX and
 * the way it works in the GNU libc implementation.
 *
 * buf_ptr is a pointer to a pointer. The latter is the buffer.
 * chunk is the size of the unit to work on.
 */

FILE *
open_memstream(char **buf_ptr, size_t *chunk) 
{    
	struct my_stream_data *mys;          /* My_stream struct */
	FILE *ret;
	if(!(mys = malloc(sizeof *mys))) 
		return 0;    
	mys->buffer=0;    	/* init to zero */
	mys->buf_size=0;    	/* init to zero */ 
	mys->allocation=0;    	/* init to zero */ 
	mys->buf_ptr=buf_ptr;   /* pointer to pointer that was handed in */
	mys->chunk = chunk;     /* logical chunk size */
	*buf_ptr = 0;    /* init to zero, allocate in write path */ 
	*chunk = 0;    	 /* init to zero */
	/* Now setup the funopen() parameters */
	ret=funopen( mys, 
	        0,  		    /* the reader */ 
		memstream_writefn,  /* the writer */
		0,  		    /* the seek   */ 
	        0);                 /* the close  */  
	return ret;
}  
