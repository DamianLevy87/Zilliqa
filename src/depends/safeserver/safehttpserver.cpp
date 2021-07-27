/*************************************************************************
 * libjson-rpc-cpp
 *************************************************************************
 * @file    httpserver.cpp
 * @date    31.12.2012
 * @author  Peter Spiess-Knafl <dev@spiessknafl.at>
 * @license See attached LICENSE.txt
 ************************************************************************/

#include "safehttpserver.h"
#include <cstdlib>
#include <sstream>
#include <cstring>
#include <iostream>
#include "jsonrpccpp/common/specificationparser.h"
#include "libUtils/Logger.h"
#include "common/Constants.h"

using namespace jsonrpc;
using namespace std;

#define BUFFERSIZE 65536

struct mhd_coninfo {
    struct MHD_PostProcessor *postprocessor;
    MHD_Connection* connection;
    stringstream request;
    SafeHttpServer* server;
    int code;
};

SafeHttpServer::SafeHttpServer(int port, bool useEpoll, const std::string &sslcert, const std::string &sslkey, int threads) :
    AbstractServerConnector(),
    port(port),
    threads(threads),
    running(false),
    useEpoll(useEpoll),
    path_sslcert(sslcert),
    path_sslkey(sslkey),
    daemon(NULL),
    bindlocalhost(false) {}

SafeHttpServer::~SafeHttpServer() {}

IClientConnectionHandler *SafeHttpServer::GetHandler(const std::string &url) {
  if (AbstractServerConnector::GetHandler() != NULL)
    return AbstractServerConnector::GetHandler();
  map<string, IClientConnectionHandler *>::iterator it =
      this->urlhandler.find(url);
  if (it != this->urlhandler.end())
    return it->second;
  return NULL;
}

bool SafeHttpServer::StartListening() {
  LOG_MARKER();

  if (!this->running) {

    unsigned int mhd_flags = 0;

    // Temp fix with useEpoll until proper solution for CLOSE_WAIT
    if (CONNECTION_IO_USE_EPOLL) {
    
      const bool has_epoll =
          (MHD_is_feature_supported(MHD_FEATURE_EPOLL) == MHD_YES);
      const bool has_poll =
          (MHD_is_feature_supported(MHD_FEATURE_POLL) == MHD_YES);

      if (has_epoll)
  // In MHD version 0.9.44 the flag is renamed to
  // MHD_USE_EPOLL_INTERNALLY_LINUX_ONLY. In later versions both
  // are deprecated.
  #if defined(MHD_USE_EPOLL_INTERNALLY)
        mhd_flags |= MHD_USE_EPOLL_INTERNALLY;
  #else
        mhd_flags |= MHD_USE_EPOLL_INTERNALLY_LINUX_ONLY | MHD_USE_ITC;
  #endif
      else if (has_poll)
        mhd_flags |= MHD_USE_POLL_INTERNALLY;
        
    } else {
      mhd_flags |= MHD_USE_SELECT_INTERNALLY;
    }

    if (this->bindlocalhost) {
      LOG_GENERAL(INFO, "Start Listening at bind localhost, mhdflag: " << mhd_flags);
      memset(&this->loopback_addr, 0, sizeof(this->loopback_addr));
      loopback_addr.sin_family = AF_INET;
      loopback_addr.sin_port = htons(this->port);
      loopback_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

      this->daemon = MHD_start_daemon(
          mhd_flags, this->port, NULL, NULL, SafeHttpServer::callback, this,
          MHD_OPTION_THREAD_POOL_SIZE, this->threads, MHD_OPTION_SOCK_ADDR,
          (struct sockaddr *)(&(this->loopback_addr)),
          MHD_OPTION_CONNECTION_TIMEOUT, CONNECTION_RPC_TIMEOUT,
           MHD_OPTION_END);

    } else if (!this->path_sslcert.empty() && !this->path_sslkey.empty()) {
      try {
        LOG_GENERAL(INFO, "Start Listening with ssl cert and key, mhdflag: " << mhd_flags);
        SpecificationParser::GetFileContent(this->path_sslcert, this->sslcert);
        SpecificationParser::GetFileContent(this->path_sslkey, this->sslkey);

        this->daemon = MHD_start_daemon(
            MHD_USE_SSL | mhd_flags, this->port, NULL, NULL,
            SafeHttpServer::callback, this, MHD_OPTION_HTTPS_MEM_KEY,
            this->sslkey.c_str(), MHD_OPTION_HTTPS_MEM_CERT,
            this->sslcert.c_str(), MHD_OPTION_THREAD_POOL_SIZE, this->threads,
            MHD_OPTION_CONNECTION_TIMEOUT, CONNECTION_RPC_TIMEOUT,
            MHD_OPTION_END);
      } catch (JsonRpcException &ex) {
        return false;
      }
    } else {
      LOG_GENERAL(INFO, "Start Listening, mhdflag: " << mhd_flags);

      if ((unsigned int)port == STAKING_RPC_PORT) {
        this->daemon = MHD_start_daemon(
          mhd_flags, this->port, SafeHttpServer::notify_policy_callback, NULL, SafeHttpServer::callback, this,
          MHD_OPTION_THREAD_POOL_SIZE, this->threads,
          // MHD_OPTION_CONNECTION_LIMIT, CONNECTION_RPC_CONNECTION_LIMIT,
          // MHD_OPTION_LISTENING_ADDRESS_REUSE, CONNECTION_RPC_REUSE,
          MHD_OPTION_CONNECTION_TIMEOUT, CONNECTION_RPC_TIMEOUT,
          MHD_OPTION_URI_LOG_CALLBACK, &SafeHttpServer::log_callback, NULL,
          MHD_OPTION_NOTIFY_COMPLETED, &SafeHttpServer::notify_completed_callback, NULL,
          MHD_OPTION_NOTIFY_CONNECTION, &SafeHttpServer::notify_connection_callback, NULL,
          MHD_OPTION_END);
      } else {
        this->daemon = MHD_start_daemon(
          mhd_flags, this->port, NULL, NULL, SafeHttpServer::callback, this,
          MHD_OPTION_THREAD_POOL_SIZE, this->threads,
          MHD_OPTION_END);
      }
    }
    if (this->daemon != NULL)
      this->running = true;
  }
  return this->running;
}

bool SafeHttpServer::StopListening() {
  LOG_MARKER();
  if (this->running) {
    LOG_GENERAL(INFO, "Stopping");
    MHD_stop_daemon(this->daemon);
    this->running = false;
  }
  return true;
}

bool SafeHttpServer::SendResponse(const string &response, void *addInfo) {
  struct mhd_coninfo *client_connection =
      static_cast<struct mhd_coninfo *>(addInfo);
  struct MHD_Response *result = MHD_create_response_from_buffer(
      response.size(), (void *)response.c_str(), MHD_RESPMEM_MUST_COPY);
  
  MHD_add_response_header(result, "Content-Type", "application/json");
  MHD_add_response_header(result, "Access-Control-Allow-Origin", "*");
  MHD_add_response_header(result,
                         MHD_HTTP_HEADER_CONNECTION,
                         "close");

  int ret = MHD_queue_response(client_connection->connection,
                               client_connection->code, result);
  MHD_destroy_response(result);
  return ret == MHD_YES;
}

bool SafeHttpServer::SendOptionsResponse(void *addInfo) {
  struct mhd_coninfo *client_connection =
      static_cast<struct mhd_coninfo *>(addInfo);
  struct MHD_Response *result =
      MHD_create_response_from_buffer(0, NULL, MHD_RESPMEM_MUST_COPY);

  MHD_add_response_header(result, "Allow", "POST, OPTIONS");
  MHD_add_response_header(result, "Access-Control-Allow-Origin", "*");
  MHD_add_response_header(result, "Access-Control-Allow-Headers",
                          "origin, content-type, accept");
  MHD_add_response_header(result, "DAV", "1");
  MHD_add_response_header(result,
                         MHD_HTTP_HEADER_CONNECTION,
                         "close");
  int ret = MHD_queue_response(client_connection->connection,
                               client_connection->code, result);
  MHD_destroy_response(result);
  return ret == MHD_YES;
}

void SafeHttpServer::SetUrlHandler(const string &url,
                               IClientConnectionHandler *handler) {
  this->urlhandler[url] = handler;
  this->SetHandler(NULL);
}

int SafeHttpServer::callback(void *cls, MHD_Connection *connection, const char *url,
                         const char *method, const char *version,
                         const char *upload_data, size_t *upload_data_size,
                         void **con_cls) {
  LOG_MARKER();
  
  
  uint16_t port = 0;
  
  auto client_addr = MHD_get_connection_info(connection, MHD_CONNECTION_INFO_CLIENT_ADDRESS)->client_addr;
  struct sockaddr_in *addr_in = (struct sockaddr_in *)client_addr;
  char *s = inet_ntoa(addr_in->sin_addr);
  port = ntohs(addr_in->sin_port);
  
  LOG_GENERAL(INFO, "SafeHttpServer callback - PORT: " << port << " IP: " << s);

  (void)version;
  if (*con_cls == NULL) {
    LOG_GENERAL(INFO, "NULL" << port);

    struct mhd_coninfo *client_connection = new mhd_coninfo;
    client_connection->connection = connection;
    client_connection->server = static_cast<SafeHttpServer *>(cls);
    *con_cls = client_connection;
    return MHD_YES;
  }

  struct mhd_coninfo *client_connection =
      static_cast<struct mhd_coninfo *>(*con_cls);
  
  if (string("POST") == method) {
    if (*upload_data_size != 0) {
      LOG_GENERAL(INFO, "upload_data_size != 0, PORT: " << port);
      client_connection->request.write(upload_data, *upload_data_size);
      *upload_data_size = 0;
      return MHD_YES;
    } else {
      string response;
      IClientConnectionHandler *handler =
          client_connection->server->GetHandler(string(url));
      if (handler == NULL) {
              LOG_GENERAL(INFO, "No client connection handler found, PORT: " << port);

        client_connection->code = MHD_HTTP_INTERNAL_SERVER_ERROR;
        client_connection->server->SendResponse(
            "No client connection handler found", client_connection);
      } else {

                      LOG_GENERAL(INFO, "HandleRequest, PORT: " << port);

        client_connection->code = MHD_HTTP_OK;
        handler->HandleRequest(client_connection->request.str(), response);
        client_connection->server->SendResponse(response, client_connection);
      }
    }
  } else if (string("OPTIONS") == method) {
                          LOG_GENERAL(INFO, "OPTIONS, PORT: " << port);

    client_connection->code = MHD_HTTP_OK;
    client_connection->server->SendOptionsResponse(client_connection);
  } else {
                              LOG_GENERAL(INFO, "Not allowed HTTP Method, PORT: " << port);

    client_connection->code = MHD_HTTP_METHOD_NOT_ALLOWED;
    client_connection->server->SendResponse("Not allowed HTTP Method",
                                            client_connection);
  }

  if (client_connection != nullptr) {
    delete client_connection;
  }
  *con_cls = NULL;

  return MHD_YES;
}

void* SafeHttpServer::log_callback(void *cls,
        const char* uri,
        struct MHD_Connection* connection)
{
  LOG_MARKER();
  (void) cls;
  (void) connection;  /* Unused. Silent compiler warning. */

  LOG_GENERAL(INFO, uri);

  return NULL;
}


void SafeHttpServer::notify_completed_callback(void* cls,
                     struct MHD_Connection* connection,
                     void** con_cls,
                     enum MHD_RequestTerminationCode toe)
{
  LOG_MARKER();

  (void) cls;
  (void) connection;  /* Unused. Silent compiler warning. */
  (void) con_cls;
  if (toe == MHD_REQUEST_TERMINATED_COMPLETED_OK) {
    LOG_GENERAL(INFO, "MHD_REQUEST_TERMINATED_COMPLETED_OK");
  } else if (toe == MHD_REQUEST_TERMINATED_WITH_ERROR) {
    LOG_GENERAL(INFO, "MHD_REQUEST_TERMINATED_WITH_ERROR");
  } else if (toe == MHD_REQUEST_TERMINATED_TIMEOUT_REACHED) {
    LOG_GENERAL(INFO, "MHD_REQUEST_TERMINATED_TIMEOUT_REACHED");
  } else if (toe == MHD_REQUEST_TERMINATED_DAEMON_SHUTDOWN) {
    LOG_GENERAL(INFO, "MHD_REQUEST_TERMINATED_DAEMON_SHUTDOWN");
  } else if (toe == MHD_REQUEST_TERMINATED_READ_ERROR) {
    LOG_GENERAL(INFO, "MHD_REQUEST_TERMINATED_READ_ERROR");
  } else if (toe == MHD_REQUEST_TERMINATED_CLIENT_ABORT) {
    LOG_GENERAL(INFO, "MHD_REQUEST_TERMINATED_CLIENT_ABORT");
    auto client_addr = MHD_get_connection_info(connection, MHD_CONNECTION_INFO_CLIENT_ADDRESS)->client_addr;
    struct sockaddr_in *addr_in = (struct sockaddr_in *)client_addr;
    char *s = inet_ntoa(addr_in->sin_addr);
    LOG_GENERAL(INFO, "IP: " << s);

  } else {
    LOG_GENERAL(INFO, "Something is wrong: " << (unsigned int)toe);
  }
}



void SafeHttpServer::notify_connection_callback(void* cls,
                      struct MHD_Connection* connection,
                      void** socket_context,
                      enum MHD_ConnectionNotificationCode toe)
{
  LOG_MARKER();
  (void) socket_context;
  (void) cls;
  
    auto client_addr = MHD_get_connection_info(connection, MHD_CONNECTION_INFO_CLIENT_ADDRESS)->client_addr;
    struct sockaddr_in *addr_in = (struct sockaddr_in *)client_addr;
    char *s = inet_ntoa(addr_in->sin_addr);
    LOG_GENERAL(INFO, "IP: " << s);

  switch (toe)
  {
  case MHD_CONNECTION_NOTIFY_STARTED:
    LOG_GENERAL(INFO, "started");
    break;
  case MHD_CONNECTION_NOTIFY_CLOSED:
    LOG_GENERAL(INFO, "stopped");
    break;
  }
}

int SafeHttpServer::notify_policy_callback(void *cls,
                             const struct sockaddr *addr,
                             socklen_t addrlen) {
    LOG_MARKER();


  (void) cls;
  (void) addrlen;

  uint16_t port = 0;
  
  struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
  char *s = inet_ntoa(addr_in->sin_addr);
  port = ntohs(addr_in->sin_port);
  
  LOG_GENERAL(INFO, "SafeHttpServer notify_policy_callback - PORT: " << port << " IP: " << s);

  // Temporary toggle
  if (CONNECTION_RPC_REUSE)
    return MHD_NO;
  

  return MHD_YES;
}

SafeHttpServer &SafeHttpServer::BindLocalhost() {
  this->bindlocalhost = true;
  return *this;
}

