import java.io.InputStream;
import java.net.URI;
import java.util.Calendar;

import org.apache.hadoop.fs.FileStatus;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.mapred.JobConf;

import p3.common.lib.BinaryUtils;
import p3.common.lib.Bytes;

//import p3.ip.analyzer.P3CoralProgram;


public class PacketFlowStats {

	static final String INPATH = "pcap_in";
	static final String OUTPATH = "PcapFlowStats_out";
	private static final int PCAP_FILE_HEADER_LENGTH = 24;  
	private static final int ONEDAYINSEC = 432000;
	
	static JobConf conf = new JobConf(FlowAnalyzer.class);
	
	public static void main(String[] args) throws Exception{
		char argtype = 0;
		String[] end = null;
		long cap_start = Long.MAX_VALUE;
		long cap_end = Long.MIN_VALUE;
		String srcFilename = new String();
		boolean rtag = false; 
		String dstFilename= OUTPATH+"/";
		int windowSize = 600;
		boolean fh_skip = true;
		
		conf.addResource("p3-default.xml");
		
		/* Argument Parsing */
		int i = 0;
		while(i<args.length){
			if(args[i].startsWith("-")){
				argtype = args[i].charAt(1);
				
				
				switch (argtype){
				
				case 'B': case 'b':					
					String[] begin = args[i].substring(2).trim().split("-");
					if(begin.length<3)
						begin = args[i].substring(2).trim().split("/");
					if (begin.length == 3) {
						Calendar cal = Calendar.getInstance( );
						cal.set(Integer.parseInt(begin[0]),
								Integer.parseInt(begin[1]),Integer.parseInt(begin[2]));
						cal.add(Calendar.MONTH, -1);
						cal.add(Calendar.DATE, -1);
						cap_start = Math.round(cal.getTimeInMillis()/1000);
					}
					break;
				
				case 'E': case 'e':
					end = args[i].substring(2).trim().split("-");
					if(end.length<3)
						end = args[i].substring(2).trim().split("/");
					if (end.length == 3) {
						Calendar cal = Calendar.getInstance( );
						cal.set(Integer.parseInt(end[0]),
								Integer.parseInt(end[1]),Integer.parseInt(end[2]));
						cal.add(Calendar.MONTH, -1);
						cal.add(Calendar.DATE, 1);
						cap_end = Math.round(cal.getTimeInMillis()/1000);
					}
					break;
				
				case 'R': case 'r':
					srcFilename += args[i].substring(2);
					rtag = true;
					break;	
					
				case 'D': case 'd':
					System.out.println(dstFilename);
					dstFilename = args[i].substring(2);
					System.out.println(dstFilename);
					break;		
					
				case 'W': case 'w':
					windowSize = Integer.parseInt(args[i].substring(2).trim());
					conf.setInt("pcap.record.rate.windowSize", windowSize);
					break;	
				
					
				default:
					
					break;
				}	
				
			}
			
			i++;
		}
		
		if (srcFilename == null) srcFilename = INPATH + "/";
		
		/* if there's input path*/
		if(rtag){
			InputStream in = null;
			Path inputPath = new Path(srcFilename);
			FileSystem fs = FileSystem.get(URI.create(srcFilename), conf);
			byte[] buffer = new byte[PCAP_FILE_HEADER_LENGTH];
			long timestamp = 0;
			
			/* extract capture time */
			if(cap_start == Long.MAX_VALUE){
				FileStatus stat = fs.getFileStatus(inputPath);
				if(stat.isDir()){
					FileStatus[] stats = fs.listStatus(inputPath);
					for(FileStatus curfs : stats){
						if(!curfs.isDir()){
							System.out.println(curfs.getPath());
							in = fs.open(curfs.getPath());
							if(fh_skip)
								in.read(buffer, 0, PCAP_FILE_HEADER_LENGTH);
							in.read(buffer, 0, 4);
							timestamp = Bytes.toInt(BinaryUtils.flipBO(buffer,4));
							
							if(timestamp < cap_start)
								cap_start = timestamp;
							if(timestamp > cap_end)
								cap_end = timestamp;
						}
					}
					in.close();
					fs.close();
					cap_end = cap_end + ONEDAYINSEC;
				} else {
					in = fs.open(inputPath);
					if(fh_skip)
						in.read(buffer, 0, PCAP_FILE_HEADER_LENGTH);
					in.read(buffer, 0, 4);
					timestamp = Bytes.toInt(BinaryUtils.flipBO(buffer,4));
					
					System.out.println(timestamp);
					cap_start = timestamp;
					
					if(cap_end == Long.MIN_VALUE){
						cap_end = cap_start+ONEDAYINSEC;
					}
					in.close();
					fs.close();
				}
				
			}
			if(cap_end == Long.MIN_VALUE)
				cap_end = cap_start+ONEDAYINSEC;
			
			Path outputDir = new Path(dstFilename);
			System.out.println(dstFilename);
			//System.exit(0);
			
			FlowAnalyzer fwAnalysis = new FlowAnalyzer(conf);
			fwAnalysis.startAnalysis(inputPath, outputDir, cap_start, cap_end);
			
		}
	}
}
