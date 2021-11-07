import { grpc } from '@improbable-eng/grpc-web';

import { host } from '../app/config';

class GrpcError extends Error {
  code: number

  message: string

  constructor(code: number, message: string) {
    super(`grpc error: code=${code}, message=${message}`);
    this.code = code;
    this.message = message;
  }
}

export const unary = async <TRequest extends grpc.ProtobufMessage, TResponse extends grpc.ProtobufMessage>(
  methodDescriptor: grpc.UnaryMethodDefinition<TRequest, TResponse>,
  request: TRequest,
  jwt?: string,
): Promise<TResponse> => {
  const metadata = new grpc.Metadata();
  if (jwt) {
    metadata.set('authorization', jwt);
  }

  return new Promise((res, rej) => {
    grpc.unary<TRequest, TResponse, grpc.UnaryMethodDefinition<TRequest, TResponse>>(methodDescriptor, {
      host,
      metadata,
      request,
      onEnd: (output) => {
        if (output.status !== grpc.Code.OK) {
          rej(new GrpcError(output.status, output.statusMessage));
          return;
        }
        if (output.message === null) {
          rej(new Error('output.message is null. this should not happen on success'));
          return;
        }
        res(output.message);
      },
    });
  });
};
