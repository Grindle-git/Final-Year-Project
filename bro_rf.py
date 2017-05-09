import os
import subprocess
import csv
import pandas as pd
import numpy as np
import argparse
from sklearn.ensemble import RandomForestClassifier
#from sklearn.tree import DecisionTreeClassifier, export_graphviz
from sklearn.cross_validation import train_test_split

parser = argparse.ArgumentParser(description="analyse Android network traffic using decision trees and return output to ABSA")
parser.add_argument("train", help="training data input", type=str)
parser.add_argument("test", help="test data input")
args = parser.parse_args()
#def help():	
def get_code(tree, feature_names, target_names,
             spacer_base="    "):
    """Produce psuedo-code for decision tree.

    Args
    ----
    tree -- scikit-leant DescisionTree.
    feature_names -- list of feature names.
    target_names -- list of target (class) names.
    spacer_base -- used for spacing code (default: "    ").

    Notes
    -----
    based on http://stackoverflow.com/a/30104792.
    """
    left      = tree.tree_.children_left
    right     = tree.tree_.children_right
    threshold = tree.tree_.threshold
    features  = [feature_names[i] for i in tree.tree_.feature]
    value = tree.tree_.value

    def recurse(left, right, threshold, features, node, depth):
        spacer = spacer_base * depth
        if (threshold[node] != -2):
            print(spacer + "if ( " + features[node] + " <= " + \
                  str(threshold[node]) + " ) {")
            if left[node] != -1:
                    recurse(left, right, threshold, features,
                            left[node], depth+1)
            print(spacer + "}\n" + spacer +"else {")
            if right[node] != -1:
                    recurse(left, right, threshold, features,
                            right[node], depth+1)
            print(spacer + "}")
        else:
            target = value[node]
            for i, v in zip(np.nonzero(target)[1],
                            target[np.nonzero(target)]):
                target_name = target_names[i]
                target_count = int(v)
                print(spacer + "return " + str(target_name) + \
                      " ( " + str(target_count) + " examples )")

    recurse(left, right, threshold, features, 0, 0)

def visualize_tree(tree, feature_names):
    """Create tree png using graphviz.

    Args
    ----
    tree -- scikit-learn DecsisionTree.
    feature_names -- list of feature names.
    """
    print tree
    print feature_names
    with open("dt.dot", 'w') as f:
        export_graphviz(tree, out_file=f,
                        feature_names=feature_names)

    command = ["dot", "-Tpng", "dt.dot", "-o", "dt.png"]
    try:
        subprocess.check_call(command)
    except:
        exit("Could not run dot, ie graphviz, to "
             "produce visualization")

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
        print("--Testing data input found: ", args.test)
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
		print ("--training data imported to data frame\n")
		df = pd.read_csv("log.csv", index_col=0)
	else:
		print("training CSV not found")
		exit()
	
	return df

def import_test():
    """Get traffic training data from specified csv"""
    if os.path.exists("test.csv"):
        print ("--testing data imported to data frame\n")
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


"""Create a new csv for analysis with DT"""
def write_rf_csv():
	#fieldnames = ['target', 'idorigh', 'idresph', 'origbytes', 'respbytes', 'origpkts', 'resppkts', 'duration', 'bps', 'byte_ratio', 'apsize']
   	print "--Writing Decision Tree CSV to example.csv"
	#print ("result \n"+str(result))
	result.to_csv('rf_convert.csv')
	os.system("cat rf_convert.csv | sed '/inf/d' > rf.csv")

def read_rf_csv():	
        """Get traffic data from local csv"""
        if os.path.exists("rf.csv"):
                print ("--decision trees CSV imported\n")
                results = pd.read_csv("rf.csv", index_col=0)
        else:
                print("log not found")

        return results

#Create a new csv for test data analysis with RF
def write_test_rf_csv():
        print "--Testing data CSV sanitised of empty rows"
        #print ("result \n"+str(result))
        test_result.to_csv('test_rf_convert.csv')
        os.system("cat test_rf_convert.csv | sed '/inf/d' > test_rf.csv")

def read_test_rf_csv():
        """testing data from local csv"""
        if os.path.exists("test_rf.csv"):
                print ("--testing CSV imported\n")
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

result = pd.concat([df, bps, byte_ratio, apsize], axis=1)
test_result = pd.concat([test_df, test_bps, test_ratio,test_apsize], axis=1)
#print test_result.head()
#print test_result.head()
#create new csv with empty rows removed - they break the analysis
write_rf_csv()
results = read_rf_csv()
write_test_rf_csv()
test_results = read_test_rf_csv()
"""Finally start the Decision Tree 'Machine Learning'!"""
#Define features
"""	1. test received bytes per flow against average col 3
		--malicious is usually 
	2. test sent bytes per flow against average col 2
	3. test received packets per flow against average col 5 
	4. test sent packets per flow against average col 4
	5. test bytes p/s against average col 8
	6. test ratio of incoming to outgoing bytes col 9
	7. test average packet size per flow  col 10"""
features = ["origbytes", "respbytes", "origpkts", "resppkts", "bps", "ratio", "avg_flow_psize"]
test_features = ["origbytes", "respbytes", "origpkts", "resppkts", "bps", "ratio", "avg_flow_psize"]
x_test_data = test_results[test_features]
print("* features:" + str(features) + "\n")
print ("* test data features: " + str(test_features) + "\n")
df_y = results["malicious"]
df_x = results[features]
x_train, x_test, y_train, y_test = train_test_split(df_x, df_y, test_size=0.2, random_state=4)
rf = RandomForestClassifier(n_estimators=100)
rf.fit(x_train, y_train)
#dt = DecisionTreeClassifier(min_samples_split=20, random_state=99)
#dt.fit(df_x, df_y)

predictions= rf.predict(x_test)
#print predictions
#print y_test.values

test_pred = rf.predict(x_test_data)

y_values = y_test.values
count = 0
for i in range(len(predictions)):
    if predictions[i]==y_values[i]:
        count = count+1

total = len(predictions)
accuracy = count/float(len(predictions)) 
print "***Training Data Results***"
print "Detected based on ", features,": ", count
print "Total: ", total 
print "Accuracy: ",accuracy
#print("\n-- get_code:")
#get_code(dt, features, df["malicious"])
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
print test_pred
