lib = File.expand_path('../lib/', __FILE__)
$LOAD_PATH.unshift lib unless $LOAD_PATH.include?(lib)
require 'strongbox/version'

Gem::Specification.new do |s|
  s.name        = 'strongbox'
  s.version     = Strongbox::VERSION
  s.authors     = ['Spike Ilacqua']
  s.email       = 'spike@stuff-things.net'

  s.homepage    = 'http://stuff-things.net/strongbox'
  s.summary     = 'Secures ActiveRecord fields with public key encryption.'
  s.description = <<-EOF
    Strongbox provides Public Key Encryption for ActiveRecord. By using a
    public key sensitive information can be encrypted and stored automatically.
    Once stored a password is required to access the information. dependencies
    are specified in standard Ruby syntax.
  EOF

  s.files      = `git ls-files`.split("\n")
  s.test_files = `git ls-files -- test/*`.split("\n")

  s.add_runtime_dependency 'activerecord'

  s.add_development_dependency 'rake', '>= 10.0.0'
  s.add_development_dependency 'rdoc', '>= 2.4.0'
  s.add_development_dependency 'sqlite3', '~> 1.3.7'
  s.add_development_dependency 'test-unit', '>= 3.0.9'
  s.add_development_dependency 'thoughtbot-shoulda', '>= 2.9.0'
end
