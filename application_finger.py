import sys
import pyshark
import csv
reload(sys)
from multiprocessing import Pool

sys.setdefaultencoding('utf8')
import sys
import pyshark
import csv
def ApplicationDataFilter(L=[]):
    return [fp[1] for fp in L if 'App' in fp[0] ]
def FingerPrintExtrator(pcap,writer):
    
    cap = pyshark.FileCapture(pcap,display_filter ="tcp contains googlevideo and ip.dst!=192.168.20.201/24")
    google_video_stream_lst= []
    for pkt in cap:
        google_video_stream_lst.append(int(pkt.tcp.stream))

    google_video_stream_lst = map(str,sorted(google_video_stream_lst))
    print 'This pcap has ',google_video_stream_lst ,'video stream'
    if  len(google_video_stream_lst)!=0:

        for idx,streamNum in enumerate(google_video_stream_lst):

            streamFilter = "tcp.stream eq " + streamNum +" and ssl" + " and ip.src!=192.168.20.201/24"
            # print streamFilter
            cap = pyshark.FileCapture(pcap,display_filter =streamFilter,only_summaries=True)
            pkt_counter = 0
            # print cap.__len__()
            # if not cap[10]:
            #     print '$$$$$$$$'
            try :
                x = cap[10]

                fingerSizeStringList = []
                fingerSizeLst = []
                for pkt_num in range(10):

                    fingerSizeStringList.append(cap[pkt_num].info)
                    fingerSizeLst.append(cap[pkt_num].length)
                if idx== 0 :
                        print pcap +'*************************************'
                        
                        print '----------------------------------------------'
                        print '1st stream:'
                        print ApplicationDataFilter(zip(fingerSizeStringList,fingerSizeLst)) 
                        writer.writerow([pcap]+ApplicationDataFilter(zip(fingerSizeStringList,fingerSizeLst)))
                if idx == 1:
                      
                        print '----------------------------------------------'
                        print '2nd stream:'

                        print ApplicationDataFilter(zip(fingerSizeStringList,fingerSizeLst))
                        writer.writerow([pcap]+ApplicationDataFilter(zip(fingerSizeStringList,fingerSizeLst)))
            except:
                print "less than $10 pkts, Droped..."



    else:
        print "useless pcap ,Droped"


def main(argv):


    if len(argv) != 2:
        print "Youtube  SSL fingerPrint extractor:"
        print "    Usage: python <PCAP dic>"
        print ""
        print argv[1]
        sys.exit(1)

    import glob
    pool = Pool()
    files = glob.glob(argv[1]+"/*.pcap")+glob.glob(argv[1]+"/*.pcapng")

    print argv[1]+"/*.pcap"
    print files
    count = 0
    #Pcap files Set
    writer = csv.writer(file('fingerPrint_Application.csv', 'ab'))
    for f in files:

        print FingerPrintExtrator(f,writer)


    # result = pool.map(FingerPrintExtrator, files)
    # print result


    # print "over"sdsds

if __name__ == "__main__":

    main(sys.argv)