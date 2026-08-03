require 'sinatra'

get '/search' do
  user_input = params[:q]
  password = params[:pass]
  api_key = "sk-1234567890abcdef"

  query = "SELECT * FROM items WHERE name = '" + user_input + "'"
  ActiveRecord::Base.connection.execute(query)

  system("grep #{user_input} /var/log/app.log")

  redirect user_input

  "<p>Hello, #{user_input}</p>"
end
