/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.apache.coyote.http11;

import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import org.apache.coyote.InputBuffer;
import org.apache.coyote.Request;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.buf.ByteChunk;
import org.apache.tomcat.util.buf.MessageBytes;
import org.apache.tomcat.util.http.HeaderUtil;
import org.apache.tomcat.util.http.MimeHeaders;
import org.apache.tomcat.util.http.parser.HttpParser;
import org.apache.tomcat.util.net.ApplicationBufferHandler;
import org.apache.tomcat.util.net.SocketWrapperBase;
import org.apache.tomcat.util.res.StringManager;

/**
 * InputBuffer for HTTP that provides request header parsing as well as transfer
 * encoding.
 */
public class Http11InputBuffer implements InputBuffer, ApplicationBufferHandler {

    // -------------------------------------------------------------- Constants

    private static final Log log = LogFactory.getLog(Http11InputBuffer.class);

    /**
     * The string manager for this package.
     */
    private static final StringManager sm = StringManager.getManager(Http11InputBuffer.class);


    // HTTP/2 创建连接时发送的一个隐秘开始报文
    private static final byte[] CLIENT_PREFACE_START =
            "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1);

    /**
     * Associated Coyote request.
     */
    private final Request request;


    /**
     * Headers of the associated request.
     */
    private final MimeHeaders headers;


    private final boolean rejectIllegalHeader;

    /**
     * State.
     */
    private volatile boolean parsingHeader;


    /**
     * Swallow input ? (in the case of an expectation)
     * 这个标识现在暂时不知道是干嘛用的，swallow 的意思是吞，在这里可能是能否继续读取的意思吧
     * 如果出现错误，他的值会被改为 false
     */
    private boolean swallowInput;


    /**
     * The read buffer.
     */
    private ByteBuffer byteBuffer;


    /**
     * Pos of the end of the header in the buffer, which is also the
     * start of the body.
     */
    private int end;


    /**
     * Wrapper that provides access to the underlying socket.
     */
    private SocketWrapperBase<?> wrapper;


    /**
     * Underlying input buffer.
     */
    private InputBuffer inputStreamInputBuffer;


    /**
     * Filter library.
     * Note: Filter[Constants.CHUNKED_FILTER] is always the "chunked" filter.
     */
    private InputFilter[] filterLibrary;


    /**
     * Active filters (in order).
     */
    private InputFilter[] activeFilters;


    /**
     * Index of the last active filter.
     */
    private int lastActiveFilter;


    /**
     * Parsing state - used for non blocking parsing so that
     * when more data arrives, we can pick up where we left off.
     */
    // 前一个字符
    private byte prevChr = 0;
    // 当前字符，这两个字符是为了处理回车换行用的
    private byte chr = 0;
    // 解析请求行标志
    private volatile boolean parsingRequestLine;
    // 解析请求头阶段
    //     0: 初始化
    //     1: 开始解析，去掉前面的回车换行符
    //     2: 解析 method
    //     3: 去掉 method 和 URI 之间的空格
    //     4: 解析 URI
    //     5: 去掉 URI 和 protocol 之间的空格
    //     6: 解析 protocol
    //     7: 复位标志
    private int parsingRequestLinePhase = 0;
    // 处理行结束标志
    private boolean parsingRequestLineEol = false;
    // 开始解析请求下标，会一直变，可以是 REQUEST_METHOD 开始的位置、URI 开始的位置、PROTOCOL_VERSION 开始的位置等等
    private int parsingRequestLineStart = 0;
    // 请求参数开始下标，就是 ?p1=v1&p2=v2 开始下标
    private int parsingRequestLineQPos = -1;
    // 解析请求头位置
    private HeaderParsePosition headerParsePos;
    private final HeaderParseData headerData = new HeaderParseData();
    private final HttpParser httpParser;

    /**
     * Maximum allowed size of the HTTP request line plus headers plus any
     * leading blank lines.
     */
    private final int headerBufferSize;

    /**
     * Known size of the NioChannel read buffer.
     */
    private int socketReadBufferSize;


    // ----------------------------------------------------------- Constructors

    public Http11InputBuffer(Request request, int headerBufferSize,
            boolean rejectIllegalHeader, HttpParser httpParser) {

        this.request = request;
        headers = request.getMimeHeaders();

        this.headerBufferSize = headerBufferSize;
        this.rejectIllegalHeader = rejectIllegalHeader;
        this.httpParser = httpParser;

        filterLibrary = new InputFilter[0];
        activeFilters = new InputFilter[0];
        lastActiveFilter = -1;

        parsingHeader = true;
        parsingRequestLine = true;
        parsingRequestLinePhase = 0;
        parsingRequestLineEol = false;
        parsingRequestLineStart = 0;
        parsingRequestLineQPos = -1;
        headerParsePos = HeaderParsePosition.HEADER_START;
        swallowInput = true;

        inputStreamInputBuffer = new SocketInputBuffer();
    }


    // ------------------------------------------------------------- Properties

    /**
     * Add an input filter to the filter library.
     *
     * @throws NullPointerException if the supplied filter is null
     */
    void addFilter(InputFilter filter) {

        if (filter == null) {
            throw new NullPointerException(sm.getString("iib.filter.npe"));
        }

        InputFilter[] newFilterLibrary = Arrays.copyOf(filterLibrary, filterLibrary.length + 1);
        newFilterLibrary[filterLibrary.length] = filter;
        filterLibrary = newFilterLibrary;

        activeFilters = new InputFilter[filterLibrary.length];
    }


    /**
     * Get filters.
     */
    InputFilter[] getFilters() {
        return filterLibrary;
    }


    /**
     * Add an input filter to the filter library.
     */
    void addActiveFilter(InputFilter filter) {

        if (lastActiveFilter == -1) {
            filter.setBuffer(inputStreamInputBuffer);
        } else {
            for (int i = 0; i <= lastActiveFilter; i++) {
                if (activeFilters[i] == filter) {
                    return;
                }
            }
            filter.setBuffer(activeFilters[lastActiveFilter]);
        }

        activeFilters[++lastActiveFilter] = filter;

        filter.setRequest(request);
    }


    /**
     * Set the swallow input flag.
     */
    void setSwallowInput(boolean swallowInput) {
        this.swallowInput = swallowInput;
    }


    // ---------------------------------------------------- InputBuffer Methods

    /**
     * @deprecated Unused. Will be removed in Tomcat 9. Use
     *             {@link #doRead(ApplicationBufferHandler)}
     */
    @Deprecated
    @Override
    public int doRead(ByteChunk chunk) throws IOException {

        if (lastActiveFilter == -1) {
            return inputStreamInputBuffer.doRead(chunk);
        } else {
            return activeFilters[lastActiveFilter].doRead(chunk);
        }

    }

    @Override
    public int doRead(ApplicationBufferHandler handler) throws IOException {
        if (lastActiveFilter == -1) {
            return inputStreamInputBuffer.doRead(handler);
        } else {
            return activeFilters[lastActiveFilter].doRead(handler);
        }
    }


    // ------------------------------------------------------- Protected Methods

    /**
     * Recycle the input buffer. This should be called when closing the
     * connection.
     */
    void recycle() {
        wrapper = null;
        request.recycle();

        for (int i = 0; i <= lastActiveFilter; i++) {
            activeFilters[i].recycle();
        }

        byteBuffer.limit(0).position(0);
        lastActiveFilter = -1;
        swallowInput = true;

        chr = 0;
        prevChr = 0;
        headerParsePos = HeaderParsePosition.HEADER_START;
        parsingRequestLinePhase = 0;
        parsingRequestLineEol = false;
        parsingRequestLineStart = 0;
        parsingRequestLineQPos = -1;
        headerData.recycle();
        // Recycled last because they are volatile
        // All variables visible to this thread are guaranteed to be visible to
        // any other thread once that thread reads the same volatile. The first
        // action when parsing input data is to read one of these volatiles.
        parsingRequestLine = true;
        parsingHeader = true;
    }


    /**
     * End processing of current HTTP request.
     * Note: All bytes of the current request should have been already
     * consumed. This method only resets all the pointers so that we are ready
     * to parse the next HTTP request.
     */
    void nextRequest() {
        request.recycle();

        if (byteBuffer.position() > 0) {
            if (byteBuffer.remaining() > 0) {
                // Copy leftover bytes to the beginning of the buffer
                byteBuffer.compact();
                byteBuffer.flip();
            } else {
                // Reset position and limit to 0
                byteBuffer.position(0).limit(0);
            }
        }

        // Recycle filters
        for (int i = 0; i <= lastActiveFilter; i++) {
            activeFilters[i].recycle();
        }

        // Reset pointers
        lastActiveFilter = -1;
        parsingHeader = true;
        swallowInput = true;

        headerParsePos = HeaderParsePosition.HEADER_START;
        parsingRequestLine = true;
        parsingRequestLinePhase = 0;
        parsingRequestLineEol = false;
        parsingRequestLineStart = 0;
        parsingRequestLineQPos = -1;
        headerData.recycle();
    }


    /**
     * Read the request line. This function is meant to be used during the
     * HTTP request header parsing. Do NOT attempt to read the request body
     * using it.
     * 解析请求行
     *
     * @throws IOException If an exception occurs during the underlying socket
     * read operations, or if the given buffer is not big enough to accommodate
     * the whole line.
     *
     * @return true if data is properly fed; false if no data is available
     * immediately and thread should be freed
     */
    boolean parseRequestLine(boolean keptAlive) throws IOException {

        // check state
        // 如果未解析请求行，返回true
        if (!parsingRequestLine) {
            return true;
        }
        //
        // Skipping blank lines
        // parsingRequestLinePhase < 2 时，表示处于忽略回车换行符阶段
        //
        if (parsingRequestLinePhase < 2) {
            do {
                // Read new bytes if needed
                // 如果需要读取新数据
                if (byteBuffer.position() >= byteBuffer.limit()) {
                    // 如果设置了 keep-alive 时间，则将 keep-alive 时间设置为读取超时时间
                    if (keptAlive) {
                        // Haven't read any request data yet so use the keep-alive
                        // timeout.
                        wrapper.setReadTimeout(wrapper.getEndpoint().getKeepAliveTimeout());
                    }
                    // 继续读取数据到缓存中
                    if (!fill(false)) {
                        // A read is pending, so no longer in initial state
                        // 读取数据挂起，将解析阶段更新为1
                        parsingRequestLinePhase = 1;
                        // 返回false表示没数据需要处理
                        return false;
                    }
                    // At least one byte of the request has been received.
                    // Switch to the socket timeout.
                    // 如果至少读取了一个字符，则将读取超时时间设置为 connection-time 连接超时时间
                    wrapper.setReadTimeout(wrapper.getEndpoint().getConnectionTimeout());
                }
                // 这里是处理 HTTP2 连接建立请求的，如果读取的长度超过 CLIENT_PREFACE_START 的大小
                if (!keptAlive && byteBuffer.position() == 0 && byteBuffer.limit() >= CLIENT_PREFACE_START.length - 1) {
                    // HTTP2 请求前置匹配标志默认为true，然后比较每个字符，对不上则更新为false
                    boolean prefaceMatch = true;
                    for (int i = 0; i < CLIENT_PREFACE_START.length && prefaceMatch; i++) {
                        if (CLIENT_PREFACE_START[i] != byteBuffer.get(i)) {
                            prefaceMatch = false;
                        }
                    }
                    // 如果匹配上 HTTP2 请求，将解析阶段设置为 -1，否则还是 HTTP1.1 请求
                    if (prefaceMatch) {
                        // HTTP/2 preface matched
                        parsingRequestLinePhase = -1;
                        return false;
                    }
                }
                // Set the start time once we start reading data (even if it is
                // just skipping blank lines)
                // 如果未设置开始时间，则更新为当前时间戳
                if (request.getStartTime() < 0) {
                    request.setStartTime(System.currentTimeMillis());
                }
                // 读取下个字符， pos+1
                chr = byteBuffer.get();
            } while ((chr == Constants.CR) || (chr == Constants.LF));
            byteBuffer.position(byteBuffer.position() - 1);

            // 设置请求开始下标
            parsingRequestLineStart = byteBuffer.position();
            // 将解析阶段更新为2，开始解析请求方法
            parsingRequestLinePhase = 2;
        }
        if (parsingRequestLinePhase == 2) {
            //
            // Reading the method name
            // Method name is a token
            //
            // 是否解析到空格标志
            boolean space = false;
            while (!space) {
                // Read new bytes if needed
                if (byteBuffer.position() >= byteBuffer.limit()) {
                    if (!fill(false)) {
                        return false;
                    }
                }
                // Spec says method name is a token followed by a single SP but
                // also be tolerant of multiple SP and/or HT.
                int pos = byteBuffer.position();
                chr = byteBuffer.get();
                if (chr == Constants.SP || chr == Constants.HT) {
                    // 如果是空格或者制表符，表示请求方式已经读取完了，更新 space 标志位为 true，并设置 request 的 method 属性为对应的请求方式字符数组
                    // 这里 method 类型为啥选择字符数组是有考虑的，可以避免编码问题和进行快速比较
                    space = true;
                    request.method().setBytes(byteBuffer.array(), parsingRequestLineStart,
                            pos - parsingRequestLineStart);
                } else if (!HttpParser.isToken(chr)) {
                    // 校验 RequestMethod 值是否正确，是正常字符则不处理，否则抛异常
                    // Avoid unknown protocol triggering an additional error
                    request.protocol().setString(Constants.HTTP_11);
                    String invalidMethodValue = parseInvalid(parsingRequestLineStart, byteBuffer);
                    throw new IllegalArgumentException(sm.getString("iib.invalidmethod", invalidMethodValue));
                }
            }
            // 下一解析阶段3，处理 REQUEST_METHOD 和 URI 之间的空格和制表符
            parsingRequestLinePhase = 3;
        }
        if (parsingRequestLinePhase == 3) {
            // Spec says single SP but also be tolerant of multiple SP and/or HT
            boolean space = true;
            while (space) {
                // Read new bytes if needed
                if (byteBuffer.position() >= byteBuffer.limit()) {
                    if (!fill(false)) {
                        return false;
                    }
                }
                chr = byteBuffer.get();
                if (!(chr == Constants.SP || chr == Constants.HT)) {
                    space = false;
                    byteBuffer.position(byteBuffer.position() - 1);
                }
            }
            // 更新解析开始的下标
            parsingRequestLineStart = byteBuffer.position();
            // 下一解析阶段4，解析 URI
            parsingRequestLinePhase = 4;
        }
        // 解析 URI
        if (parsingRequestLinePhase == 4) {
            // Mark the current buffer position

            int end = 0;
            //
            // Reading the URI
            //
            boolean space = false;
            while (!space) {
                // Read new bytes if needed
                if (byteBuffer.position() >= byteBuffer.limit()) {
                    if (!fill(false)) {
                        return false;
                    }
                }
                int pos = byteBuffer.position();
                prevChr = chr;
                chr = byteBuffer.get();
                // 如果前一个字符是回车符，但是当前字符不是换行符的话，抛异常
                if (prevChr == Constants.CR && chr != Constants.LF) {
                    // CR not followed by LF so not an HTTP/0.9 request and
                    // therefore invalid. Trigger error handling.
                    // Avoid unknown protocol triggering an additional error
                    request.protocol().setString(Constants.HTTP_11);
                    String invalidRequestTarget = parseInvalid(parsingRequestLineStart, byteBuffer);
                    throw new IllegalArgumentException(sm.getString("iib.invalidRequestTarget", invalidRequestTarget));
                }
                if (chr == Constants.SP || chr == Constants.HT) {
                    space = true;
                    end = pos;
                } else if (chr == Constants.CR) {
                    // HTTP/0.9 style request. CR is optional. LF is not.
                } else if (chr == Constants.LF) {
                    // 走这里表示是 HTTP/0.9 请求，因为如果是 HTTP/1.1 的话，会在第一个条件的时候就被拦截掉
                    // HTTP/0.9 style request
                    // Stop this processing loop
                    space = true;
                    // Set blank protocol (indicates HTTP/0.9)
                    // 设置协议为空
                    request.protocol().setString("");
                    // Skip the protocol processing
                    parsingRequestLinePhase = 7;
                    // 处理 pos，因为 HTTP09 的 回车符不是必须的，所以要处理掉
                    if (prevChr == Constants.CR) {
                        end = pos - 1;
                    } else {
                        end = pos;
                    }
                } else if (chr == Constants.QUESTION && parsingRequestLineQPos == -1) {
                    // 如果是请求参数开始字符，也就是?，那么设置参数开始的位置下标
                    parsingRequestLineQPos = pos;
                } else if (parsingRequestLineQPos != -1 && !httpParser.isQueryRelaxed(chr)) {
                    // Avoid unknown protocol triggering an additional error
                    request.protocol().setString(Constants.HTTP_11);
                    // %nn decoding will be checked at the point of decoding
                    String invalidRequestTarget = parseInvalid(parsingRequestLineStart, byteBuffer);
                    throw new IllegalArgumentException(sm.getString("iib.invalidRequestTarget", invalidRequestTarget));
                } else if (httpParser.isNotRequestTargetRelaxed(chr)) {
                    // Avoid unknown protocol triggering an additional error
                    request.protocol().setString(Constants.HTTP_11);
                    // This is a general check that aims to catch problems early
                    // Detailed checking of each part of the request target will
                    // happen in Http11Processor#prepareRequest()
                    String invalidRequestTarget = parseInvalid(parsingRequestLineStart, byteBuffer);
                    throw new IllegalArgumentException(sm.getString("iib.invalidRequestTarget", invalidRequestTarget));
                }
            }
            // 设置 QUERY_STRING 和 URI
            if (parsingRequestLineQPos >= 0) {
                request.queryString().setBytes(byteBuffer.array(), parsingRequestLineQPos + 1,
                        end - parsingRequestLineQPos - 1);
                request.requestURI().setBytes(byteBuffer.array(), parsingRequestLineStart,
                        parsingRequestLineQPos - parsingRequestLineStart);
            } else {
                request.requestURI().setBytes(byteBuffer.array(), parsingRequestLineStart,
                        end - parsingRequestLineStart);
            }
            // HTTP/0.9 processing jumps to stage 7.
            // Don't want to overwrite that here.
            // 如果当前阶段是4，则进入阶段5，处理 URI 和 PROTOCOL 之间的空格
            if (parsingRequestLinePhase == 4) {
                parsingRequestLinePhase = 5;
            }
        }
        // 处理 URI 和 PROTOCOL 之间的空格
        if (parsingRequestLinePhase == 5) {
            // Spec says single SP but also be tolerant of multiple and/or HT
            boolean space = true;
            while (space) {
                // Read new bytes if needed
                if (byteBuffer.position() >= byteBuffer.limit()) {
                    if (!fill(false)) {
                        return false;
                    }
                }
                byte chr = byteBuffer.get();
                if (!(chr == Constants.SP || chr == Constants.HT)) {
                    space = false;
                    byteBuffer.position(byteBuffer.position() - 1);
                }
            }
            parsingRequestLineStart = byteBuffer.position();
            parsingRequestLinePhase = 6;

            // Mark the current buffer position
            end = 0;
        }
        // 解析 HTTP 协议版本
        if (parsingRequestLinePhase == 6) {
            //
            // Reading the protocol
            // Protocol is always "HTTP/" DIGIT "." DIGIT
            //
            while (!parsingRequestLineEol) {
                // Read new bytes if needed
                if (byteBuffer.position() >= byteBuffer.limit()) {
                    if (!fill(false)) {
                        return false;
                    }
                }

                int pos = byteBuffer.position();
                prevChr = chr;
                chr = byteBuffer.get();
                if (chr == Constants.CR) {
                    // Possible end of request line. Need LF next else invalid.
                } else if (prevChr == Constants.CR && chr == Constants.LF) {
                    // CRLF is the standard line terminator
                    end = pos - 1;
                    parsingRequestLineEol = true;
                } else if (chr == Constants.LF) {
                    // LF is an optional line terminator
                    end = pos;
                    parsingRequestLineEol = true;
                } else if (prevChr == Constants.CR || !HttpParser.isHttpProtocol(chr)) {
                    String invalidProtocol = parseInvalid(parsingRequestLineStart, byteBuffer);
                    throw new IllegalArgumentException(sm.getString("iib.invalidHttpProtocol", invalidProtocol));
                }
            }

            // 设置 HTTP 请求协议版本号
            if ((end - parsingRequestLineStart) > 0) {
                request.protocol().setBytes(byteBuffer.array(), parsingRequestLineStart,
                        end - parsingRequestLineStart);
                parsingRequestLinePhase = 7;
            }
            // If no protocol is found, the ISE below will be triggered.
        }
        // 恢复标志位
        if (parsingRequestLinePhase == 7) {
            // Parsing is complete. Return and clean-up.
            parsingRequestLine = false;
            parsingRequestLinePhase = 0;
            parsingRequestLineEol = false;
            parsingRequestLineStart = 0;
            return true;
        }
        throw new IllegalStateException(sm.getString("iib.invalidPhase", Integer.valueOf(parsingRequestLinePhase)));
    }


    /**
     * Parse the HTTP headers.
     * 解析请求头
     */
    boolean parseHeaders() throws IOException {
        if (!parsingHeader) {
            throw new IllegalStateException(sm.getString("iib.parseheaders.ise.error"));
        }

        HeaderParseStatus status = HeaderParseStatus.HAVE_MORE_HEADERS;

        do {
            status = parseHeader();
            // Checking that
            // (1) Headers plus request line size does not exceed its limit
            // (2) There are enough bytes to avoid expanding the buffer when
            // reading body
            // Technically, (2) is technical limitation, (1) is logical
            // limitation to enforce the meaning of headerBufferSize
            // From the way how buf is allocated and how blank lines are being
            // read, it should be enough to check (1) only.
            if (byteBuffer.position() > headerBufferSize || byteBuffer.capacity() - byteBuffer.position() < socketReadBufferSize) {
                throw new IllegalArgumentException(sm.getString("iib.requestheadertoolarge.error"));
            }
        } while (status == HeaderParseStatus.HAVE_MORE_HEADERS);
        if (status == HeaderParseStatus.DONE) {
            parsingHeader = false;
            end = byteBuffer.position();
            return true;
        } else {
            return false;
        }
    }


    int getParsingRequestLinePhase() {
        return parsingRequestLinePhase;
    }


    private String parseInvalid(int startPos, ByteBuffer buffer) {
        // Look for the next space
        byte b = 0;
        while (buffer.hasRemaining() && b != 0x20) {
            b = buffer.get();
        }
        String result = HeaderUtil.toPrintableString(buffer.array(), buffer.arrayOffset() + startPos, buffer.position() - startPos);
        if (b != 0x20) {
            // Ran out of buffer rather than found a space
            result = result + "...";
        }
        return result;
    }


    /**
     * End request (consumes leftover bytes).
     *
     * @throws IOException an underlying I/O error occurred
     */
    void endRequest() throws IOException {

        if (swallowInput && (lastActiveFilter != -1)) {
            int extraBytes = (int) activeFilters[lastActiveFilter].end();
            byteBuffer.position(byteBuffer.position() - extraBytes);
        }
    }


    @Override
    public int available() {
        return available(false);
    }


    /**
     * Available bytes in the buffers for the current request.
     *
     * Note that when requests are pipelined, the data in byteBuffer may relate
     * to the next request rather than this one.
     */
    int available(boolean read) {
        int available;

        if (lastActiveFilter == -1) {
            available = inputStreamInputBuffer.available();
        } else {
            available = activeFilters[lastActiveFilter].available();
        }

        // Only try a non-blocking read if:
        // - there is no data in the filters
        // - the caller requested a read
        // - there is no data in byteBuffer
        // - the socket wrapper indicates a read is allowed
        //
        // Notes: 1. When pipelined requests are being used available may be
        //        zero even when byteBuffer has data. This is because the data
        //        in byteBuffer is for the next request. We don't want to
        //        attempt a read in this case.
        //        2. wrapper.hasDataToRead() is present to handle the NIO2 case
        try {
            if (available == 0 && read && !byteBuffer.hasRemaining() && wrapper.hasDataToRead()) {
                fill(false);
                available = byteBuffer.remaining();
            }
        } catch (IOException ioe) {
            if (log.isDebugEnabled()) {
                log.debug(sm.getString("iib.available.readFail"), ioe);
            }
            // Not ideal. This will indicate that data is available which should
            // trigger a read which in turn will trigger another IOException and
            // that one can be thrown.
            available = 1;
        }
        return available;
    }


    /**
     * Has all of the request body been read? There are subtle differences
     * between this and available() &gt; 0 primarily because of having to handle
     * faking non-blocking reads with the blocking IO connector.
     */
    boolean isFinished() {
        // The active filters have the definitive information on whether or not
        // the current request body has been read. Note that byteBuffer may
        // contain pipelined data so is not a good indicator.
        if (lastActiveFilter >= 0) {
            return activeFilters[lastActiveFilter].isFinished();
        } else {
            // No filters. Assume request is not finished. EOF will signal end of
            // request.
            return false;
        }
    }

    ByteBuffer getLeftover() {
        int available = byteBuffer.remaining();
        if (available > 0) {
            return ByteBuffer.wrap(byteBuffer.array(), byteBuffer.position(), available);
        } else {
            return null;
        }
    }


    void init(SocketWrapperBase<?> socketWrapper) {

        wrapper = socketWrapper;
        wrapper.setAppReadBufHandler(this);

        int bufLength = headerBufferSize +
                wrapper.getSocketBufferHandler().getReadBuffer().capacity();
        if (byteBuffer == null || byteBuffer.capacity() < bufLength) {
            byteBuffer = ByteBuffer.allocate(bufLength);
            byteBuffer.position(0).limit(0);
        }
    }



    // --------------------------------------------------------- Private Methods

    /**
     * Attempts to read some data into the input buffer.
     * 读取数据到buffer
     * 如果读取字符大于0，返回true
     *            等于0，返回false
     *            等于-1，抛异常
     *
     * @return <code>true</code> if more data was added to the input buffer
     *         otherwise <code>false</code>
     */
    private boolean fill(boolean block) throws IOException {

        if (log.isDebugEnabled()) {
            log.debug("Before fill(): parsingHeader: [" + parsingHeader +
                    "], parsingRequestLine: [" + parsingRequestLine +
                    "], parsingRequestLinePhase: [" + parsingRequestLinePhase +
                    "], parsingRequestLineStart: [" + parsingRequestLineStart +
                    "], byteBuffer.position(): [" + byteBuffer.position() +
                    "], byteBuffer.limit(): [" + byteBuffer.limit() +
                    "], end: [" + end + "]");
        }

        if (parsingHeader) {
            if (byteBuffer.limit() >= headerBufferSize) {
                if (parsingRequestLine) {
                    // Avoid unknown protocol triggering an additional error
                    request.protocol().setString(Constants.HTTP_11);
                }
                throw new IllegalArgumentException(sm.getString("iib.requestheadertoolarge.error"));
            }
        } else {
            byteBuffer.limit(end).position(end);
        }

        int nRead = -1;
        int mark = byteBuffer.position();
        try {
            if (byteBuffer.position() < byteBuffer.limit()) {
                byteBuffer.position(byteBuffer.limit());
            }
            byteBuffer.limit(byteBuffer.capacity());
            nRead = wrapper.read(block, byteBuffer);
        } finally {
            // Ensure that the buffer limit and position are returned to a
            // consistent "ready for read" state if an error occurs during in
            // the above code block.
            // Some error conditions can result in the position being reset to
            // zero which also invalidates the mark.
            // https://bz.apache.org/bugzilla/show_bug.cgi?id=65677
            if (byteBuffer.position() >= mark) {
                // // Position and mark are consistent. Assume a read (possibly
                // of zero bytes) has occurred.
                byteBuffer.limit(byteBuffer.position());
                byteBuffer.position(mark);
            } else {
                // Position and mark are inconsistent. Set position and limit to
                // zero so effectively no data is reported as read.
                byteBuffer.position(0);
                byteBuffer.limit(0);
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("Received ["
                    + new String(byteBuffer.array(), byteBuffer.position(), byteBuffer.remaining(), StandardCharsets.ISO_8859_1) + "]");
        }

        if (nRead > 0) {
            return true;
        } else if (nRead == -1) {
            throw new EOFException(sm.getString("iib.eof.error"));
        } else {
            return false;
        }

    }


    /**
     * Parse an HTTP header.
     * 解析单个请求头
     *
     * @return One of {@link HeaderParseStatus#NEED_MORE_DATA},
     * {@link HeaderParseStatus#HAVE_MORE_HEADERS} or
     * {@link HeaderParseStatus#DONE}.
     */
    private HeaderParseStatus parseHeader() throws IOException {

        // 处理请求行和请求头之间的回车换行符
        while (headerParsePos == HeaderParsePosition.HEADER_START) {

            // Read new bytes if needed
            if (byteBuffer.position() >= byteBuffer.limit()) {
                if (!fill(false)) {
                    return HeaderParseStatus.NEED_MORE_DATA;
                }
            }

            prevChr = chr;
            chr = byteBuffer.get();

            if (chr == Constants.CR && prevChr != Constants.CR) {
                // Possible start of CRLF - process the next byte.
            } else if (chr == Constants.LF) {
                // CRLF or LF is an acceptable line terminator
                // 第一个字符是回车符表示请求头已经处理完了，也就是请求头和请求体之间的空行，该行不能有空格符和制表符
                return HeaderParseStatus.DONE;
            } else {
                if (prevChr == Constants.CR) {
                    // Must have read two bytes (first was CR, second was not LF)
                    byteBuffer.position(byteBuffer.position() - 2);
                } else {
                    // Must have only read one byte
                    byteBuffer.position(byteBuffer.position() - 1);
                }
                break;
            }
        }

        // 记录开始处理的请求头位置下标
        if (headerParsePos == HeaderParsePosition.HEADER_START) {
            // Mark the current buffer position
            headerData.start = byteBuffer.position();
            headerData.lineStart = headerData.start;
            headerParsePos = HeaderParsePosition.HEADER_NAME;
        }

        //
        // Reading the header name
        // Header name is always US-ASCII
        //
        // 处理请求头名字
        while (headerParsePos == HeaderParsePosition.HEADER_NAME) {

            // Read new bytes if needed
            if (byteBuffer.position() >= byteBuffer.limit()) {
                if (!fill(false)) { // parse header
                    return HeaderParseStatus.NEED_MORE_DATA;
                }
            }

            int pos = byteBuffer.position();
            chr = byteBuffer.get();
            // 如果是 header 和 value 的分隔符，则更新解析位置为值开始，并更新
            if (chr == Constants.COLON) {
                headerParsePos = HeaderParsePosition.HEADER_VALUE_START;
                // 读取 header 名
                headerData.headerValue = headers.addValue(byteBuffer.array(), headerData.start,
                        pos - headerData.start);
                // 更新下标，此时对应的是 HEADER_VALUE_START 的值的下标了，而不是 HEADER_START 的值的下标
                pos = byteBuffer.position();
                // Mark the current buffer position
                headerData.start = pos;
                headerData.realPos = pos;
                headerData.lastSignificantChar = pos;
                break;
            } else if (!HttpParser.isToken(chr)) {
                // Non-token characters are illegal in header names
                // Parsing continues so the error can be reported in context
                // 如果不是符合的字符，跳过该行
                headerData.lastSignificantChar = pos;
                byteBuffer.position(byteBuffer.position() - 1);
                // skipLine() will handle the error
                return skipLine();
            }

            // chr is next byte of header name. Convert to lowercase.
            // header 名转化为小写
            if ((chr >= Constants.A) && (chr <= Constants.Z)) {
                byteBuffer.put(pos, (byte) (chr - Constants.LC_OFFSET));
            }
        }

        // Skip the line and ignore the header
        // 如果忽略当前行，则更新标志下标信息
        if (headerParsePos == HeaderParsePosition.HEADER_SKIPLINE) {
            return skipLine();
        }

        //
        // Reading the header value (which can be spanned over multiple lines)
        //
        // 读取请求头的值，可以处理多行

        while (headerParsePos == HeaderParsePosition.HEADER_VALUE_START ||
               headerParsePos == HeaderParsePosition.HEADER_VALUE ||
               headerParsePos == HeaderParsePosition.HEADER_MULTI_LINE) {

            // 位置为解析值开始时忽略空格和制表符，比如我们使用 -H 'content-type: application/json' 这里就有一个空格
            if (headerParsePos == HeaderParsePosition.HEADER_VALUE_START) {
                // Skipping spaces
                while (true) {
                    // Read new bytes if needed
                    if (byteBuffer.position() >= byteBuffer.limit()) {
                        if (!fill(false)) {// parse header
                            // HEADER_VALUE_START
                            return HeaderParseStatus.NEED_MORE_DATA;
                        }
                    }

                    chr = byteBuffer.get();
                    if (!(chr == Constants.SP || chr == Constants.HT)) {
                        // 跳过所有空格后设置请求头解析位置为解析值
                        headerParsePos = HeaderParsePosition.HEADER_VALUE;
                        byteBuffer.position(byteBuffer.position() - 1);
                        break;
                    }
                }
            }
            // 解析请求头的值
            // 当读取值时，headerData.realPos.pos 和 headerData.realPos 的距离就是多行中多余的空格数量
            // buf 的值会被修改，将空格前移
            if (headerParsePos == HeaderParsePosition.HEADER_VALUE) {

                // Reading bytes until the end of the line
                // 行位标志符
                boolean eol = false;
                while (!eol) {

                    // Read new bytes if needed
                    if (byteBuffer.position() >= byteBuffer.limit()) {
                        if (!fill(false)) {// parse header
                            // HEADER_VALUE
                            return HeaderParseStatus.NEED_MORE_DATA;
                        }
                    }

                    prevChr = chr;
                    chr = byteBuffer.get();
                    if (chr == Constants.CR) {
                        // Possible start of CRLF - process the next byte.
                    } else if (chr == Constants.LF) {
                        // CRLF or LF is an acceptable line terminator
                        eol = true;
                    } else if (prevChr == Constants.CR) {
                        // Invalid value
                        // Delete the header (it will be the most recent one)
                        // 值不允许出现回车符，否则忽略该行，删除前面添加的 header 并重置行读取标志
                        headers.removeHeader(headers.size() - 1);
                        return skipLine();
                    } else if (chr != Constants.HT && HttpParser.isControl(chr)) {
                        // Invalid value
                        // Delete the header (it will be the most recent one)
                        // 字符不是制表符但是是控制符，也不行
                        headers.removeHeader(headers.size() - 1);
                        return skipLine();
                    } else if (chr == Constants.SP || chr == Constants.HT) {
                        byteBuffer.put(headerData.realPos, chr);
                        headerData.realPos++;
                    } else {
                        byteBuffer.put(headerData.realPos, chr);
                        headerData.realPos++;
                        headerData.lastSignificantChar = headerData.realPos;
                    }
                }

                // Ignore whitespaces at the end of the line
                headerData.realPos = headerData.lastSignificantChar;

                // Checking the first character of the new line. If the character
                // is a LWS, then it's a multiline header
                headerParsePos = HeaderParsePosition.HEADER_MULTI_LINE;
            }
            // Read new bytes if needed
            if (byteBuffer.position() >= byteBuffer.limit()) {
                if (!fill(false)) {// parse header
                    // HEADER_MULTI_LINE
                    return HeaderParseStatus.NEED_MORE_DATA;
                }
            }

            byte peek = byteBuffer.get(byteBuffer.position());
            if (headerParsePos == HeaderParsePosition.HEADER_MULTI_LINE) {
                if ((peek != Constants.SP) && (peek != Constants.HT)) {
                    headerParsePos = HeaderParsePosition.HEADER_START;
                    break;
                } else {
                    // Copying one extra space in the buffer (since there must
                    // be at least one space inserted between the lines)
                    // 更新值的空格符（空格前移）
                    byteBuffer.put(headerData.realPos, peek);
                    headerData.realPos++;
                    headerParsePos = HeaderParsePosition.HEADER_VALUE_START;
                }
            }
        }
        // Set the header value
        // 设置 header 的值
        headerData.headerValue.setBytes(byteBuffer.array(), headerData.start,
                headerData.lastSignificantChar - headerData.start);
        // 重置标志位
        headerData.recycle();
        return HeaderParseStatus.HAVE_MORE_HEADERS;
    }


    private HeaderParseStatus skipLine() throws IOException {
        headerParsePos = HeaderParsePosition.HEADER_SKIPLINE;
        boolean eol = false;

        // Reading bytes until the end of the line
        while (!eol) {

            // Read new bytes if needed
            if (byteBuffer.position() >= byteBuffer.limit()) {
                if (!fill(false)) {
                    return HeaderParseStatus.NEED_MORE_DATA;
                }
            }

            int pos = byteBuffer.position();
            prevChr = chr;
            chr = byteBuffer.get();
            if (chr == Constants.CR) {
                // Skip
            } else if (chr == Constants.LF) {
                // CRLF or LF is an acceptable line terminator
                eol = true;
            } else {
                headerData.lastSignificantChar = pos;
            }
        }
        if (rejectIllegalHeader || log.isDebugEnabled()) {
            String message = sm.getString("iib.invalidheader",
                    HeaderUtil.toPrintableString(byteBuffer.array(), headerData.lineStart,
                            headerData.lastSignificantChar - headerData.lineStart + 1));
            if (rejectIllegalHeader) {
                throw new IllegalArgumentException(message);
            }
            log.debug(message);
        }

        headerParsePos = HeaderParsePosition.HEADER_START;
        return HeaderParseStatus.HAVE_MORE_HEADERS;
    }


    // ----------------------------------------------------------- Inner classes

    private enum HeaderParseStatus {
        DONE, HAVE_MORE_HEADERS, NEED_MORE_DATA
    }


    private enum HeaderParsePosition {
        /**
         * Start of a new header. A CRLF here means that there are no more
         * headers. Any other character starts a header name.
         */
        HEADER_START,
        /**
         * Reading a header name. All characters of header are HTTP_TOKEN_CHAR.
         * Header name is followed by ':'. No whitespace is allowed.<br>
         * Any non-HTTP_TOKEN_CHAR (this includes any whitespace) encountered
         * before ':' will result in the whole line being ignored.
         */
        HEADER_NAME,
        /**
         * Skipping whitespace before text of header value starts, either on the
         * first line of header value (just after ':') or on subsequent lines
         * when it is known that subsequent line starts with SP or HT.
         */
        HEADER_VALUE_START,
        /**
         * Reading the header value. We are inside the value. Either on the
         * first line or on any subsequent line. We come into this state from
         * HEADER_VALUE_START after the first non-SP/non-HT byte is encountered
         * on the line.
         */
        HEADER_VALUE,
        /**
         * Before reading a new line of a header. Once the next byte is peeked,
         * the state changes without advancing our position. The state becomes
         * either HEADER_VALUE_START (if that first byte is SP or HT), or
         * HEADER_START (otherwise).
         */
        HEADER_MULTI_LINE,
        /**
         * Reading all bytes until the next CRLF. The line is being ignored.
         */
        HEADER_SKIPLINE
    }


    private static class HeaderParseData {
        /**
         * The first character of the header line.
         */
        int lineStart = 0;
        /**
         * When parsing header name: first character of the header.<br>
         * When skipping broken header line: first character of the header.<br>
         * When parsing header value: first character after ':'.
         */
        int start = 0;
        /**
         * When parsing header name: not used (stays as 0).<br>
         * When skipping broken header line: not used (stays as 0).<br>
         * When parsing header value: starts as the first character after ':'.
         * Then is increased as far as more bytes of the header are harvested.
         * Bytes from buf[pos] are copied to buf[realPos]. Thus the string from
         * [start] to [realPos-1] is the prepared value of the header, with
         * whitespaces removed as needed.<br>
         */
        int realPos = 0;
        /**
         * When parsing header name: not used (stays as 0).<br>
         * When skipping broken header line: last non-CR/non-LF character.<br>
         * When parsing header value: position after the last not-LWS character.<br>
         */
        int lastSignificantChar = 0;
        /**
         * MB that will store the value of the header. It is null while parsing
         * header name and is created after the name has been parsed.
         */
        MessageBytes headerValue = null;
        public void recycle() {
            lineStart = 0;
            start = 0;
            realPos = 0;
            lastSignificantChar = 0;
            headerValue = null;
        }
    }


    // ------------------------------------- InputStreamInputBuffer Inner Class

    /**
     * This class is an input buffer which will read its data from an input
     * stream.
     */
    private class SocketInputBuffer implements InputBuffer {

        /**
         *
         * @deprecated Unused. Will be removed in Tomcat 9. Use
         *             {@link #doRead(ApplicationBufferHandler)}
         */
        @Deprecated
        @Override
        public int doRead(ByteChunk chunk) throws IOException {

            if (byteBuffer.position() >= byteBuffer.limit()) {
                // The application is reading the HTTP request body which is
                // always a blocking operation.
                if (!fill(true)) {
                    return -1;
                }
            }

            int length = byteBuffer.remaining();
            chunk.setBytes(byteBuffer.array(), byteBuffer.position(), length);
            byteBuffer.position(byteBuffer.limit());

            return length;
        }

        @Override
        public int doRead(ApplicationBufferHandler handler) throws IOException {

            if (byteBuffer.position() >= byteBuffer.limit()) {
                // The application is reading the HTTP request body
                boolean block = (request.getReadListener() == null);
                if (!fill(block)) {
                    if (block) {
                        return -1;
                    } else {
                        return 0;
                    }
                }
            }

            int length = byteBuffer.remaining();
            handler.setByteBuffer(byteBuffer.duplicate());
            byteBuffer.position(byteBuffer.limit());

            return length;
        }

        @Override
        public int available() {
            return byteBuffer.remaining();
        }
    }


    @Override
    public void setByteBuffer(ByteBuffer buffer) {
        byteBuffer = buffer;
    }


    @Override
    public ByteBuffer getByteBuffer() {
        return byteBuffer;
    }


    @Override
    public void expand(int size) {
        if (byteBuffer.capacity() >= size) {
            byteBuffer.limit(size);
        }
        ByteBuffer temp = ByteBuffer.allocate(size);
        temp.put(byteBuffer);
        byteBuffer = temp;
        byteBuffer.mark();
        temp = null;
    }
}
