
#include <iostream>
#include <memory>
#include <string>
#include <fstream>
#include <sstream>

#include <grpc++/grpc++.h>

#include "suresecureivs.grpc.pb.h"

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;
using suresecureivs::Empty;
using suresecureivs::GeneralReply;
using suresecureivs::DeviceMgt;

class MyCustomAuthenticator : public grpc::MetadataCredentialsPlugin {
public:
  MyCustomAuthenticator(const grpc::string &ticket) : ticket_(ticket) {}

  grpc::Status
  GetMetadata(grpc::string_ref service_url, grpc::string_ref method_name,
              const grpc::AuthContext &channel_auth_context,
              std::multimap<grpc::string, grpc::string> *metadata) override {
    metadata->insert(std::make_pair("x-custom-auth-ticket", ticket_));
    metadata->insert(std::make_pair("token", "mytoken"));
    return grpc::Status::OK;
  }

private:
  grpc::string ticket_;
};

class DeviceMgtClient {
public:
  DeviceMgtClient(std::shared_ptr<Channel> channel)
      : stub_(DeviceMgt::NewStub(channel)) {}

  // Assambles the client's payload, sends it and presents the response back
  // from the server.
  std::string GetHealthyStatus() {
    // Data we are sending to the server.
    Empty request;
    // Container for the data we expect from the server.
    GeneralReply reply;

    // Context for the client. It could be used to convey extra information to
    // the server and/or tweak certain RPC behaviors.
    ClientContext context;

    //context.AddMetadata("token", "mytoken");

    // The actual RPC.
    Status status = stub_->GetHealthyStatus(&context, request, &reply);

    // Act upon its status.
    if (status.ok()) {
      return reply.message();
    } else {
      return "RPC failed";
    }
  }

private:
  std::unique_ptr<DeviceMgt::Stub> stub_;
};

std::string ReadFile2String(std::string file_name) {
  std::ifstream t(file_name);
  std::stringstream buffer;
  buffer << t.rdbuf();
  return buffer.str();
}

int main(int argc, char **argv) {
  // Instantiate the client. It requires a channel, out of which the actual RPCs
  // are created. This channel models a connection to an endpoint (in this case,
  // localhost at port 50051). We indicate that the channel isn't authenticated
  // (use of InsecureChannelCredentials()).
  // EventReportingClient reporter(grpc::CreateChannel(
  //    "192.168.3.42:50051", grpc::InsecureChannelCredentials()));
  auto cacert = ReadFile2String("ca.crt");
  auto options = grpc::SslCredentialsOptions();
  options.pem_root_certs = cacert;
  auto creds = grpc::SslCredentials(options);

  auto call_creds = grpc::MetadataCredentialsFromPlugin(
      std::unique_ptr<grpc::MetadataCredentialsPlugin>(
          new MyCustomAuthenticator("super-secret-ticket")));

  auto com_creds = grpc::CompositeChannelCredentials(creds, call_creds);

  // DeviceMgtClient reporter(grpc::CreateChannel(
  //"mythxcq-ThinkPad-T430:50051", creds));
  // DeviceMgtClient reporter(grpc::CreateChannel(
  //"localhost:50051", grpc::InsecureChannelCredentials()));
  DeviceMgtClient reporter(grpc::CreateChannel("localhost:50051", com_creds));
  std::string reply = reporter.GetHealthyStatus();
  std::cout << "Reporter received: " << reply << std::endl;

  return 0;
}
