# encoding: utf-8
require "logstash-input-http_jars"
require "base64"
require "htauth"

module LogStash module Inputs class Http
  class MessageHandler
    include org.logstash.plugins.inputs.http.IMessageHandler

    attr_reader :input

    def initialize(input, default_codec, additional_codecs, auth_token, htpasswd)
      @input = input
      @default_codec = default_codec
      @additional_codecs = additional_codecs
      @auth_token = auth_token
      @htpasswd = htpasswd
    end

    def validates_token(token)
      if @htpasswd
        authenticate_user(token)
      elsif @auth_token
        @auth_token == token
      else
        true
      end
    end

    def authenticate_user(token)
      if token.nil?
        false
      else
        authed = false
        begin
          user, pw = Base64.decode64(token.sub('Basic ', '')).split(':')
          HTAuth::PasswdFile.open(@htpasswd) do |pf|
            authed = pf.authenticated?(user, pw)
          end
        rescue
            authed = false
        end
        return authed
      end
    end

    def onNewMessage(remote_address, headers, body)
      @input.decode_body(headers, remote_address, body, @default_codec, @additional_codecs)
    end

    def copy
      MessageHandler.new(@input, @default_codec.clone, clone_additional_codecs(), @auth_token, @htpasswd)
    end

    def clone_additional_codecs
      clone_additional_codecs = {}
      @additional_codecs.each do |content_type, codec|
        clone_additional_codecs[content_type] = codec.clone
      end
      clone_additional_codecs
    end

    def response_headers
      @input.response_headers
    end
  end
end; end; end
