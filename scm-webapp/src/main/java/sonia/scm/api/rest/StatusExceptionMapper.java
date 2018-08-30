/*
  Copyright (c) 2010, Sebastian Sdorra All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

  1. Redistributions of source code must retain the above copyright notice,
  this list of conditions and the following disclaimer. 2. Redistributions in
  binary form must reproduce the above copyright notice, this list of
  conditions and the following disclaimer in the documentation and/or other
  materials provided with the distribution. 3. Neither the name of SCM-Manager;
  nor the names of its contributors may be used to endorse or promote products
  derived from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE FOR
  ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

  http://bitbucket.org/sdorra/scm-manager

 */



package sonia.scm.api.rest;

//~--- non-JDK imports --------------------------------------------------------

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;

//~--- JDK imports ------------------------------------------------------------

/**
 *
 * @author Sebastian Sdorra
 * @param <E>
 */
public class StatusExceptionMapper<E extends Throwable>
  implements ExceptionMapper<E>
{

  /**
   * the logger for StatusExceptionMapper
   */
  private static final Logger logger =
    LoggerFactory.getLogger(StatusExceptionMapper.class);

  private final Response.Status status;
  private final Class<E> type;

  /**
   * Map an Exception to a HTTP Response
   *
   * @param type the exception class
   * @param status the http status to be mapped
   */
  public StatusExceptionMapper(Class<E> type, Response.Status status)
  {
    this.type = type;
    this.status = status;
  }

  /**
   * provide a http responses from an exception
   *
   * @param exception the thrown exception
   *
   * @return the http response with the exception presentation
   */
  @Override
  public Response toResponse(E exception)
  {
    if (logger.isDebugEnabled())
    {
      StringBuilder msg = new StringBuilder();

      msg.append("map ").append(type.getSimpleName()).append("to status code ");
      msg.append(status.getStatusCode());
      logger.debug(msg.toString());
    }

    return Response.status(status).build();
  }
}
