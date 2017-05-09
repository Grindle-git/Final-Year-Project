import os
import subprocess
import csv
import pandas as pd
import numpy as np
import argparse
from sklearn.ensemble import RandomForestClassifier
#from sklearn.tree import DecisionTreeClassifier, export_graphviz
from sklearn.model_selection import train_test_split
from pandas_ml import ConfusionMatrix

parser = argparse.ArgumentParser(description="analyse Android network traffic using decision trees and return output to ABSA")
parser.add_argument("train", help="training data input", type=str)
parser.add_argument("test", help="test data input")
args = parser.parse_args()

def create_initial_csv():
	"""check bro conn.log training data is present"""
	if os.path.exists(args.train):
		print("--Training data input found: ", args.train)
		#quick and dirty create csv file
		headers = os.system("echo idorigh,idresph,origbytes,respbytes,origpkts,resppkts,duration > log.csv")
		brocut = os.system("cat "+str(args.train)+"| bro-cut id.orig_h id.resp_h orig_bytes resp_bytes orig_pkts resp_pkts duration | sed 's/	/\,/g' | sed '/-/d'>> log.csv")
		
	else:
		print("Bro training data input "+str(args.train)+" not found - needs to be in working directory")
		exit()
	
def create_test_csv():
    """check bro conn.log training data is present"""
    if os.path.exists(args.test):
        print("--Traffic input for analysis found: ", args.test)
        #quick and dirty create csv file
        headers = os.system("echo idorigh,idresph,origbytes,respbytes,origpkts,resppkts,duration > test.csv")
        brocut = os.system("cat "+str(args.test)+"| bro-cut id.orig_h id.resp_h orig_bytes resp_bytes orig_pkts resp_pkts duration | sed 's/	/\,/g' | sed '/-/d'>> test.csv")
        
    else:
        print("Bro testing data input "+str(args.test)+" not found - needs to be in working directory")
        exit()

# Import data from created log.csv
def import_data():
	"""Get traffic training data from specified csv"""
	if os.path.exists("log.csv"):
		#print ("--training data imported to data frame\n")
		df = pd.read_csv("log.csv", index_col=0)
	else:
		print("training CSV not found")
		exit()
	
	return df

def import_test():
    """Get traffic training data from specified csv"""
    if os.path.exists("test.csv"):
        #print ("--testing data imported to data frame\n")
        test_df = pd.read_csv("test.csv", index_col=0)
    else:
        print("training CSV not found")
        exit()
    
    return test_df

# Calculate bandwidth. size/duration. bps
def bps_add(df, duration_column, respbytes_column):

    df_mod = df.copy()
    #to_drop = ['-']
    #df_mod = df_mod[~df_mod['duration'].isin(to_drop)]
    #df_mod = df_mod[(df_mod.duration.map(type) == float) & (df_mod.respbytes.map(type) == float)]
    #print str(df_mod)
#    print ("---------\nrespbytes column: \n" + str(df_mod[respbytes_column]) + "\n---------")
#    print ("---------\nduration column: \n" + str(df_mod[duration_column]) + "\n---------")
    df_mod["bps"] = df_mod[respbytes_column]/df_mod[duration_column]
#    print ("bps: \n"+str(bps)+"\n-----")
    return df_mod["bps"]

# Calculate ratio of incoming and outgoing bytes
def ratio(df, incoming, outgoing):
	df_mod = df.copy()
	#df_mod = df_mod[(df_mod.origbytes.map(type) == float) & (df_mod.respbytes.map(type) == float)]
	df_mod["ratio"] = df_mod[incoming]/ df_mod[outgoing]
	return df_mod["ratio"]

def avg_p_size_flow(df, opkt, rpkt, obyte, rbyte):
	df_mod = df.copy()
	df_mod["avg_flow_psize"] = ((df_mod[opkt]/df_mod[obyte])+(df_mod[rpkt]/df_mod[rbyte]))/2
	#print ("Average packet size: \n"+str(df_mod["avg_flow_psize"]))
	return df_mod["avg_flow_psize"]

def id_malicious():
	df["malicious"] = np.nan
	df.loc[df["idresph"] == "164.132.42.156", "malicious"] = 1
	df.loc[df["idresph"] != "164.132.42.156", "malicious"] = 0

def inf_malicious():
    test_df["malicious"] = np.nan
    test_df.loc[test_df["idresph"] == "144.76.109.61", "malicious"] = 1
    test_df.loc[test_df["idresph"] != "144.76.109.61", "malicious"] = 0
"""Create a new csv for analysis with DT"""
def write_rf_csv():
	#fieldnames = ['target', 'idorigh', 'idresph', 'origbytes', 'respbytes', 'origpkts', 'resppkts', 'duration', 'bps', 'byte_ratio', 'apsize']
   	#print "--Writing Decision Tree CSV to example.csv"
	#print ("result \n"+str(result))
	result.to_csv('rf_convert.csv')
	os.system("cat rf_convert.csv | sed '/inf/d' > rf.csv")

def read_rf_csv():	
        """Get traffic data from local csv"""
        if os.path.exists("rf.csv"):
                #print ("--decision trees CSV imported\n")
                results = pd.read_csv("rf.csv", index_col=0)
        else:
                print("log not found")

        return results

#Create a new csv for test data analysis with RF
def write_test_rf_csv():
        #print "--Testing data CSV sanitised of empty rows"
        #print ("result \n"+str(result))
        test_result.to_csv('test_rf_convert.csv')
        os.system("cat test_rf_convert.csv | sed '/inf/d' > test_rf.csv")

def read_test_rf_csv():
        """testing data from local csv"""
        if os.path.exists("test_rf.csv"):
                #print ("--testing CSV imported\n")
                results = pd.read_csv("test_rf.csv", index_col=0)
        else:
                print("log not found")

        return results


#Calculations/Processing
def processing(xdf):
        bps = bps_add(xdf, "duration", "respbytes")
        byte_ratio = ratio(xdf, "respbytes", "origbytes")
        apsize = avg_p_size_flow(xdf , "origpkts", "resppkts", "origbytes", "respbytes")
        avg_r_bytes = xdf["respbytes"].mean()
        avg_s_bytes = xdf["origbytes"].mean()
        avg_r_pkts = xdf["resppkts"].mean()
        avg_s_pkts = xdf["origpkts"].mean()
        avg_r_bps = bps.mean()
        avg_p_size = (avg_r_bytes + avg_s_bytes)/2
        avg_ratio = byte_ratio.mean()
        return xdf, bps, byte_ratio, apsize

def writeoutput(output):
    f = open('results.txt', 'w')
    f.write(output)
    f.close()

#Create CSV inputs for dataframe import from both training and test data
create_initial_csv()
create_test_csv()

#Import training and test data to dataframes
df = import_data()
test_df = import_test()
#process data for training and testing data frames
df, bps, byte_ratio, apsize = processing(df)
test_df, test_bps, test_ratio, test_apsize = processing(test_df)

#definite malicious rows for training data
id_malicious()
print "--Random Forests input calculated:\n"

#IDed malicious rows for test data for final confirmation of accuracy on unknown malware detection
inf_malicious()
#training data to be analysed
result = pd.concat([df, bps, byte_ratio, apsize], axis=1)
#testing data to be analyses
test_result = pd.concat([test_df, test_bps, test_ratio,test_apsize], axis=1)
#create new csv with empty rows removed - they break the analysis
write_rf_csv()
results = read_rf_csv()
results2 = results.dropna()
write_test_rf_csv()
test_results = read_test_rf_csv()
test_results2 = test_results.dropna()
#RANDOM FORESTS
#Define features
"""	1. test received bytes per flow against average col 3
		--malicious is usually 
	2. test sent bytes per flow against average col 2
	3. test received packets per flow against average col 5 
	4. test sent packets per flow against average col 4
	5. test bytes p/s against average col 8
	6. test ratio of incoming to outgoing bytes col 9
	7. test average packet size per flow  col 10"""
#Training
#define features
features = ["origbytes", "respbytes", "origpkts", "resppkts", "bps", "ratio", "avg_flow_psize"]
print("* features:" + str(features) + "\n")
#set Y to be malicious or non malicious (preclassified)
df_y = results2["malicious"]
#set X to be the features
df_x = results2[features]
#print results2[features]
#split the data set into training and testing data
x_train, x_test, y_train, y_test = train_test_split(df_x, df_y, test_size=0.2, random_state=4)
#train the machine
rf = RandomForestClassifier(n_estimators=100)
rf.fit(x_train, y_train)
#take unclassified x test values from training data set
predictions= rf.predict(x_test)
#set variable for classification of x test values
y_values = y_test.values
#find how many in x_test match those in y_values
count = 0
for i in range(len(predictions)):
    if predictions[i]==y_values[i]:
        count = count+1

cm = ConfusionMatrix(y_values, predictions)
print "***Training Data Results***"
print "Detected based on ", features,": ", count
#print "True true positives: " + TTP
print cm
print "\nConfusion Matrix stats:"
cm.print_stats()
#testing
test_features = ["origbytes", "respbytes", "origpkts", "resppkts", "bps", "ratio", "avg_flow_psize"]
x_test_data = test_results2[test_features]
y_test_data = test_results2["malicious"]
y_test_values = y_test_data.values
print ("* test data features: " + str(test_features) + "\n")
#test new x values against previously trained machine
test_pred = rf.predict(x_test_data)
print test_pred
print "\n***Real Test Results***"
unique, counts = np.unique(test_pred, return_counts=True)
nonmal = int(counts[0])
if len(counts)>1:
    mal = int(counts[1])
    total = mal+nonmal
    print "Total flows analysed: " + str(total)
    print "Malicious: " + str(mal)
else:
    total = nonmal
print "Non-malicious: " + str(nonmal)
print "\n --Real malware Confusion Matrix post analysis-- \n"
print "Confusion Matrix \n"

inf_cm = ConfusionMatrix(test_pred, y_test_values)
print inf_cm
inf_cm.print_stats()
