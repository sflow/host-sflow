/* This software is distributed under the following license:
 * http://host-sflow.sourceforge.net/license.html
 */

#include "xmlUtil.h"
	
/**
 * Creates an ISequentialStream from a string
 */
// ISequentialStream
HRESULT STDMETHODCALLTYPE CStringStream::Read(void *pv, ULONG cb, ULONG *pcbRead)
{
	HRESULT hr = S_OK;
	for (*pcbRead = 0; *pcbRead < cb; ++*pcbRead, ++m_buffSeekIndex) {
		// we are seeking past the end of the buffer
		if (m_buffSeekIndex == m_buffSize) {
			hr = S_FALSE;
			break;
		}
		((BYTE*)pv)[*pcbRead] = ((BYTE*)m_pBuffer)[m_buffSeekIndex];
	}
	return hr;
}

HRESULT STDMETHODCALLTYPE CStringStream::Write(const void *pv, ULONG cb, ULONG *pcbWritten)
{
	return E_NOTIMPL;
}

	// IUnknown
STDMETHODIMP_(ULONG) CStringStream::AddRef()
{
	return InterlockedIncrement(&m_cRef);
}

STDMETHODIMP_(ULONG) CStringStream::Release()
{
	LONG cRef = InterlockedDecrement(&m_cRef);
	if (0 == cRef) {
		delete this;
	}
	return cRef;
}

STDMETHODIMP CStringStream::QueryInterface(REFIID riid, void **ppv)
{
	HRESULT hr = S_OK;
	if (ppv) {
		*ppv = NULL;
	} else {
		hr = E_INVALIDARG;
	}
	if (S_OK == hr) {
		if ((__uuidof(IUnknown) == riid) || (riid == __uuidof(ISequentialStream))) {
				AddRef();
				*ppv = (ISequentialStream*)this;
		} else {
			hr = E_NOINTERFACE;
		}
	}
	return hr;
}

// constructor/deconstructor
CStringStream::CStringStream(BSTR bstr)
		:
		m_cRef(1), 
		m_pBuffer(bstr), 
		m_buffSize((SysStringLen(bstr)+1)*sizeof(wchar_t)),
		m_buffSeekIndex(0)
{
}
