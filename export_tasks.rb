require 'json'

# Assuming op is already defined and has tasks association
tasks_data = op.tasks.map do |task|
  task.attributes
end

# Write to file.json
File.open('file.json', 'w') do |file|
  file.write(JSON.pretty_generate(tasks_data))
end

puts "Tasks have been exported to file.json" 