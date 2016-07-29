/* This software is distributed under the following license:
 * http://sflow.net/license.html
 */
#ifndef XML_UTIL_H
#define XML_UTIL_H 1

#include <ObjIdl.h>

class CStringStream : public ISequentialStream 
{
private:
		LONG m_cRef;
		wchar_t *m_pBuffer;
		size_t m_buffSize;
		size_t m_buffSeekIndex;
	public: 
		CStringStream(BSTR bstr);
		HRESULT STDMETHODCALLTYPE Read(void *pv, ULONG cb, ULONG *pcbRead);
		HRESULT STDMETHODCALLTYPE Write(const void *pv, ULONG cb, ULONG *pcbWritten);
		STDMETHODIMP_(ULONG) AddRef();
		STDMETHODIMP_(ULONG) Release();
		STDMETHODIMP QueryInterface(REFIID riid, void **ppv);
};

#endif /* XML_API_H */