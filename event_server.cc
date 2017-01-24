#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <grpc++/grpc++.h>
#include <fstream>
#include <sstream>

#include "suresecureivs.grpc.pb.h"

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;
using suresecureivs::Empty;
// using suresecureivs::EventServerAddress;
using suresecureivs::GeneralReply;
using suresecureivs::DeviceMgt;
using grpc::SslServerCredentialsOptions;

const std::string kUsername = "username";
const std::string kPassword = "password";

class MyServiceAuthProcessor : public grpc::AuthMetadataProcessor {

public:
  grpc::Status Process(const InputMetadata &auth_metadata,
                       grpc::AuthContext *context,
                       OutputMetadata *consumed_auth_metadata,
                       OutputMetadata *response_metadata) override {

    // determine intercepted method
    std::string dispatch_keyname = ":path";
    auto dispatch_kv = auth_metadata.find(dispatch_keyname);
    if (dispatch_kv == auth_metadata.end())
      return grpc::Status(grpc::StatusCode::INTERNAL, "Internal Error");
    //std::cout << dispatch_kv->first.data() << ": " << dispatch_kv->second.data()
              //<< std::endl;

    // if token metadata not necessary, return early, avoid token checking
    auto dispatch_value = std::string(dispatch_kv->second.data());
    if (dispatch_value == "/MyPackage.MyService/Authenticate")
      return grpc::Status::OK;

    // determine availability of token metadata
    auto username_kv = auth_metadata.find(kUsername);
    auto password_kv = auth_metadata.find(kPassword);
    if (username_kv == auth_metadata.end() || password_kv == auth_metadata.end())
      return grpc::Status(grpc::StatusCode::UNAUTHENTICATED, "Missing username or password");

    //std::cout << "Token value: " << token_kv->second.data() << std::endl;

    // determine validity of token metadata
    auto username = std::string(username_kv->second.data());
    auto password = std::string(password_kv->second.data());
    //if (tokens.count(token_value) == 0)
    if(username != username_ || password != password_)
      return grpc::Status(grpc::StatusCode::UNAUTHENTICATED, "Invalid username and password");

    //std::cout << "username: " << username << std::endl;
    //std::cout << "password: " << password << std::endl;

    //// once verified, mark as consumed and store user for later retrieval
    // consumed_auth_metadata->insert(
    // std::make_pair(Const::TokenKeyName(), token_value)); // required
    // context->AddProperty(Const::PeerIdentityPropertyName(),
    // tokens[token_value]); // optional
    // context->SetPeerIdentityPropertyName(
    // Const::PeerIdentityPropertyName()); // optional

    return grpc::Status::OK;
  }
private:
  std::string username_ = "useradmin";
  std::string password_ = "1qaz@wsx";

  //std::map<std::string, std::string> tokens;
};

class DeviceMgtImpl final : public DeviceMgt::Service {
  Status GetHealthyStatus(ServerContext *context, const Empty *request,
                          GeneralReply *reply) override {
    const std::multimap<grpc::string_ref, grpc::string_ref> &metadata_map =
        context->client_metadata();
    //for (auto s : metadata_map) {
      //std::cout << s.first << "\t" << s.second << std::endl;
    //}
    reply->set_message("ok");
    return Status::OK;
  }
};

std::string ReadFile2String(std::string file_name) {
  std::ifstream t(file_name);
  std::stringstream buffer;
  buffer << t.rdbuf();
  return buffer.str();
}

void RunServer() {
  std::string server_address("0.0.0.0:50051");
  DeviceMgtImpl device_mgt_service;
  // DeviceMgtServiceImpl device_mgt_service;
  //
  // auto channel_creds = grpc::SslCredentials(grpc::SslCredentialsOptions());
  auto cacert = ReadFile2String("ca.crt");
  //std::cout << "ca.crt: " << cacert << std::endl;
  auto servercert = ReadFile2String("server.crt");
  auto serverkey = ReadFile2String("server.key");
  SslServerCredentialsOptions::PemKeyCertPair key_pair;
  key_pair.private_key = serverkey;
  key_pair.cert_chain = servercert;
  SslServerCredentialsOptions options(GRPC_SSL_DONT_REQUEST_CLIENT_CERTIFICATE);
  options.pem_root_certs = cacert;
  options.pem_key_cert_pairs.push_back(key_pair);
  auto sslCredentials = SslServerCredentials(options);

  std::shared_ptr<MyServiceAuthProcessor> auth_processor =
      std::shared_ptr<MyServiceAuthProcessor>(new MyServiceAuthProcessor());

  sslCredentials->SetAuthMetadataProcessor(auth_processor);

  ServerBuilder builder;
  // Listen on the given address without any authentication mechanism.
  // builder.AddListeningPort(server_address,
  // grpc::InsecureServerCredentials());
  builder.AddListeningPort(server_address, sslCredentials);
  // builder.AddListeningPort(server_address, channel_creds);
  // Register "service" as the instance through which we'll communicate with
  // clients. In this case it corresponds to an *synchronous* service.
  builder.RegisterService(&device_mgt_service);
  // builder.RegisterService(&device_mgt_service);
  // Finally assemble the server.
  std::unique_ptr<Server> server(builder.BuildAndStart());
  std::cout << "Server listening on " << server_address << std::endl;

  // Wait for the server to shutdown. Note that some other thread must be
  // responsible for shutting down the server for this call to ever return.
  server->Wait();
}

int main(int argc, char **argv) {
  RunServer();

  return 0;
}
