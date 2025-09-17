# app.rb - Ruby version using Opal

require 'digest'

def buffer_to_hex(buffer)
  buffer.unpack('H*').first
end

def run_benchmarks(file_data)
  results = []
  [
    ['MD5', Digest::MD5],
    ['SHA1', Digest::SHA1],
    ['SHA256', Digest::SHA256],
    ['SHA512', Digest::SHA512]
  ].each do |algo_name, algo_class|
    start = Time.now
    hash_hex = algo_class.hexdigest(file_data)
    finish = Time.now
    results << {
      name: "#{algo_name} (Ruby)",
      hash: hash_hex,
      time: (finish - start) * 1000 # ms
    }
  end
  results
end

# Opal will call this
def benchmark(file_bytes)
  run_benchmarks(file_bytes)
end