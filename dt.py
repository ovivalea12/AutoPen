# Load libraries
import pandas as pd
from sklearn.tree import DecisionTreeClassifier # Import Decision Tree Classifier
from sklearn.model_selection import train_test_split # Import train_test_split function
from sklearn import metrics #Import scikit-learn metrics module for accuracy calculation
from sklearn.tree import export_graphviz
from sklearn import preprocessing
from sklearn import tree
# from sklearn.externals.six import StringIO
from IPython.display import Image
import pydotplus
import graphviz

col_names = ['port', 'service', 'cve', 'exploit', 'os']
# load dataset
autopen = pd.read_csv("autopen_dataset.csv", header=None, names=col_names)
autopen = autopen.iloc[1:]
lE = preprocessing.LabelEncoder()

autopen = autopen.apply(lE .fit_transform)
print(autopen.head())
#split dataset in features and target variable
feature_cols = ['port', 'service', 'cve', 'os']
X = autopen[feature_cols] # Features
y = autopen.exploit # Target variable

print(autopen.head())

# Split dataset into training set and test set
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=1) # 70% training and 30% test
# Create Decision Tree classifer object
clf = tree.DecisionTreeClassifier()
#clf = DecisionTreeClassifier(criterion="entropy", max_depth=3)
# Train Decision Tree Classifer
clf = clf.fit(X_train,y_train)

#Predict the response for test dataset
y_pred = clf.predict(X_test)
# Model Accuracy, how often is the classifier correct?
print("Accuracy:",metrics.accuracy_score(y_test, y_pred))
tree.plot_tree(clf)
dot_data = tree.export_graphviz(clf, out_file=None)
graph = graphviz.Source(dot_data)
graph.render("autopen")

pydot_graph = pydotplus.graph_from_dot_data(dot_data)
Image(pydot_graph.create_png())
# dot_data = StringIO()
# export_graphviz(clf, out_file=dot_data,
#                 filled=True, rounded=True,
#                 special_characters=True,feature_names = feature_cols,class_names=['0','1'])
# graph = pydotplus.graph_from_dot_data(dot_data.getvalue())
# graph.write_png('exploits.png')
# Image(graph.create_png())
