module Fluent
  require 'fluent/mixin/config_placeholders'

  class FTPOutput < Fluent::TimeSlicedOutput
    Fluent::Plugin.register_output('ftp', self)

    def initialize
      super
      require 'net/ftp'
      require 'zlib'
      require 'time'
      require 'tempfile'
      require 'open3'
      require 'pathname'
    end

    config_param :path, :string, :default => ""
    config_param :time_format, :string, :default => nil

    include SetTagKeyMixin
    config_set_default :include_tag_key, false

    include SetTimeKeyMixin
    config_set_default :include_time_key, false

    config_param :ftp_server, :string
    config_param :ftp_user, :string
    config_param :ftp_password, :string
    config_param :ftp_dir, :string
    config_param :ftp_file_name_format, :string, :default => "%{path}%{time_slice}_%{index}.%{file_extension}"
    config_param :store_as, :string, :default => "gzip"

    include Fluent::Mixin::ConfigPlaceholders

    def placeholders
      [:percent]
    end

    def configure(conf)
      super

      if format_json = conf['format_json']
        @format_json = true
      else
        @format_json = false
      end

      @timef = TimeFormatter.new(@time_format, @localtime)

      @ext = case @store_as
        when 'gzip' then 'gz'
        when 'lzo' then
          begin
            Open3.capture3('lzop -V')
          rescue Errno::ENOENT
            raise ConfigError, "'lzop' utility must be in PATH for LZO compression"
          end
          'lzo'
        when 'json' then 'json'
        else 'txt'
      end

      if @localtime
        @path_slicer = Proc.new { |path| Time.now.strftime(path) }
      else
        @path_slicer = Proc.new { |path| Time.now.utc.strftime(path) }
      end
    end

    def start
      super
      with_ftp_connection { |conn|
        # check valid connection here, nothing to do
      }
    end

    def format(tag, time, record)
      if @include_time_key || !@format_json
        time_str = @timef.format(time)
      end

      # copied from each mixin because current TimeSlicedOutput can't support mixins.
      if @include_tag_key
        record[@tag_key] = tag
      end
      if @include_time_key
        record[@time_key] = time_str
      end

      if @format_json
        Yajl.dump(record) + "\n"
      else
        "#{time_str}\t#{tag}\t#{Yajl.dump(record)}\n"
      end
    end

    def write(chunk)
      with_ftp_connection { |conn|
        ftp_filename = gen_ftp_filename(conn, chunk.key)
        with_compression(@store_as, chunk) { |tmp_path|
          conn.putbinaryfile(tmp_path, ftp_filename)
        }
      }
    end

    private

    def with_ftp_connection
      ftp = Net::FTP.new
      ftp.binary = true
      begin
        ftp.connect(@ftp_server)
        ftp.login(@ftp_user, @ftp_password)
        ftp.chdir(@ftp_dir)
        yield ftp
      ensure
        ftp.quit() rescue nil
      end
    end

    def gen_ftp_filename(conn, chunk_key)
      i = 0
      begin
        values_for_ftp_file_name = {
          "path" => @path_slicer.call(@path),
          "time_slice" => chunk_key,
          "file_extension" => @ext,
          "index" => i
        }
        ftp_file_name = @ftp_file_name_format.gsub(%r(%{[^}]+})) { |expr|
          values_for_ftp_file_name[expr[2...expr.size-1]]
        }
        i += 1
      end while ftp_file_exists?(conn, ftp_file_name)
      return ftp_file_name
    end

    def ftp_file_exists?(conn, filename)
      begin
        not conn.nlst(filename).empty?
      rescue Net::FTPTempError => e
        err_code = e.message[0,3].to_i
        return false if err_code == 450
        raise e
      end
    end

    def with_compression(codec, chunk)
      tmp = Tempfile.new("ftp-")
      begin
        if codec == "gzip"
          w = Zlib::GzipWriter.new(tmp)
          chunk.write_to(w)
          w.close
        elsif codec == "lzo"
          w = Tempfile.new("chunk-tmp")
          chunk.write_to(w)
          w.close
          tmp.close
          # we don't check the return code because we can't recover lzop failure.
          system "lzop -qf1 -o #{tmp.path} #{w.path}"
        else
          chunk.write_to(tmp)
          tmp.close
        end
        yield Pathname.new(tmp.path)
      ensure
        tmp.close(true) rescue nil
        w.close rescue nil
        w.unlink rescue nil
      end
    end
  end
end
