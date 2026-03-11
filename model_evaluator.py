"""
AI Network Security Guard - Model Evaluator
Test and evaluate the trained anomaly detection model
"""

import pandas as pd
import numpy as np
import pickle
from sklearn.metrics import classification_report, confusion_matrix, roc_curve, auc
import matplotlib.pyplot as plt
from datetime import datetime
from config import DATASET_CONFIG, MODEL_CONFIG, PATHS
from utils import logger

class ModelEvaluator:
    """
    Evaluate and test the trained anomaly detection model
    """
    
    def __init__(self, model_path=None, scaler_path=None, features_path=None):
        """Initialize evaluator with model paths"""
        self.model_path = model_path or MODEL_CONFIG['model_path']
        self.scaler_path = scaler_path or MODEL_CONFIG['scaler_path']
        self.features_path = features_path or MODEL_CONFIG['features_path']
        
        self.model = None
        self.scaler = None
        self.features = None
        
        self._load_model()
    
    def _load_model(self):
        """Load trained model and preprocessing objects"""
        try:
            with open(self.model_path, 'rb') as f:
                self.model = pickle.load(f)
            
            with open(self.scaler_path, 'rb') as f:
                self.scaler = pickle.load(f)
            
            with open(self.features_path, 'rb') as f:
                self.features = pickle.load(f)
            
            logger.info("✅ Model loaded successfully for evaluation")
        except Exception as e:
            logger.error(f"❌ Failed to load model: {e}")
            raise
    
    def load_test_data(self):
        """Load NSL-KDD test dataset"""
        logger.info("📥 Loading test dataset...")
        
        try:
            df = pd.read_csv(DATASET_CONFIG['train_file'], 
                           names=DATASET_CONFIG['columns'], 
                           header=None)
            
            # Create binary labels (1 = normal, -1 = attack)
            df['binary_label'] = df['label'].apply(lambda x: 1 if x == 'normal' else -1)
            
            # Extract features
            X_test = df[self.features].fillna(0)
            y_test = df['binary_label']
            
            logger.info(f"📊 Test data loaded: {len(X_test)} samples")
            logger.info(f"   Normal: {sum(y_test == 1)}, Attacks: {sum(y_test == -1)}")
            
            return X_test, y_test, df
            
        except Exception as e:
            logger.error(f"❌ Failed to load test data: {e}")
            return None, None, None
    
    def evaluate_model(self, X_test, y_test):
        """
        Evaluate model performance
        
        Args:
            X_test: Test features
            y_test: Test labels (1 = normal, -1 = attack)
            
        Returns:
            Dictionary of evaluation metrics
        """
        logger.info("🔍 Evaluating model performance...")
        
        # Scale features
        X_scaled = self.scaler.transform(X_test)
        
        # Predict
        y_pred = self.model.predict(X_scaled)
        
        # Calculate metrics
        from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
        
        metrics = {
            'accuracy': accuracy_score(y_test, y_pred),
            'precision': precision_score(y_test, y_pred, pos_label=-1),  # -1 is anomaly
            'recall': recall_score(y_test, y_pred, pos_label=-1),
            'f1_score': f1_score(y_test, y_pred, pos_label=-1),
        }
        
        # Confusion matrix
        cm = confusion_matrix(y_test, y_pred, labels=[1, -1])
        metrics['confusion_matrix'] = cm
        metrics['true_negatives'] = cm[0, 0]
        metrics['false_positives'] = cm[0, 1]
        metrics['false_negatives'] = cm[1, 0]
        metrics['true_positives'] = cm[1, 1]
        
        # Detection rate
        metrics['detection_rate'] = metrics['true_positives'] / (metrics['true_positives'] + metrics['false_negatives'])
        metrics['false_alarm_rate'] = metrics['false_positives'] / (metrics['false_positives'] + metrics['true_negatives'])
        
        return metrics
    
    def print_evaluation_results(self, metrics):
        """Print evaluation results in a formatted way"""
        print("\n" + "=" * 70)
        print("📊 MODEL EVALUATION RESULTS")
        print("=" * 70)
        print(f"Accuracy:        {metrics['accuracy']:.4f} ({metrics['accuracy']*100:.2f}%)")
        print(f"Precision:       {metrics['precision']:.4f}")
        print(f"Recall:          {metrics['recall']:.4f}")
        print(f"F1-Score:        {metrics['f1_score']:.4f}")
        print(f"Detection Rate:  {metrics['detection_rate']:.4f} ({metrics['detection_rate']*100:.2f}%)")
        print(f"False Alarm Rate: {metrics['false_alarm_rate']:.4f} ({metrics['false_alarm_rate']*100:.2f}%)")
        print("\nConfusion Matrix:")
        print("                Predicted Normal  |  Predicted Attack")
        print(f"Actual Normal:       {metrics['true_negatives']:6d}      |      {metrics['false_positives']:6d}")
        print(f"Actual Attack:       {metrics['false_negatives']:6d}      |      {metrics['true_positives']:6d}")
        print("=" * 70)
    
    def test_on_attack_types(self, df):
        """Test model performance on different attack types"""
        logger.info("🔍 Testing on different attack types...")
        
        attack_types = df[df['label'] != 'normal']['label'].unique()
        
        results = {}
        
        for attack_type in attack_types:
            attack_data = df[df['label'] == attack_type]
            
            if len(attack_data) == 0:
                continue
            
            X_attack = attack_data[self.features].fillna(0)
            X_scaled = self.scaler.transform(X_attack)
            
            predictions = self.model.predict(X_scaled)
            
            # Detection rate for this attack type
            detected = sum(predictions == -1)
            total = len(predictions)
            detection_rate = detected / total if total > 0 else 0
            
            results[attack_type] = {
                'total': total,
                'detected': detected,
                'detection_rate': detection_rate
            }
        
        return results
    
    def print_attack_type_results(self, results):
        """Print detection rates for different attack types"""
        print("\n" + "=" * 70)
        print("🎯 DETECTION RATES BY ATTACK TYPE")
        print("=" * 70)
        print(f"{'Attack Type':<25} | {'Total':<8} | {'Detected':<10} | {'Rate':<8}")
        print("-" * 70)
        
        for attack_type, stats in sorted(results.items(), key=lambda x: x[1]['detection_rate'], reverse=True):
            print(f"{attack_type:<25} | {stats['total']:<8} | {stats['detected']:<10} | {stats['detection_rate']*100:>6.2f}%")
        
        print("=" * 70)
    
    def test_sample_packets(self, n_samples=10):
        """Test model on sample packets and show predictions"""
        logger.info(f"🧪 Testing on {n_samples} sample packets...")
        
        X_test, y_test, df = self.load_test_data()
        
        if X_test is None:
            return
        
        # Get random samples
        indices = np.random.choice(len(X_test), n_samples, replace=False)
        
        print("\n" + "=" * 70)
        print("🧪 SAMPLE PACKET PREDICTIONS")
        print("=" * 70)
        
        for idx in indices:
            features = X_test.iloc[idx:idx+1]
            true_label = df.iloc[idx]['label']
            
            X_scaled = self.scaler.transform(features)
            prediction = self.model.predict(X_scaled)[0]
            score = self.model.score_samples(X_scaled)[0]
            
            pred_label = "NORMAL" if prediction == 1 else "ANOMALY"
            correct = "✓" if (prediction == -1 and true_label != 'normal') or (prediction == 1 and true_label == 'normal') else "✗"
            
            print(f"{correct} True: {true_label:<20} | Predicted: {pred_label:<10} | Score: {score:>7.4f}")
        
        print("=" * 70)
    
    def generate_evaluation_report(self):
        """Generate comprehensive evaluation report"""
        logger.info("📄 Generating evaluation report...")
        
        # Load test data
        X_test, y_test, df = self.load_test_data()
        
        if X_test is None:
            logger.error("Cannot generate report without test data")
            return
        
        # Evaluate model
        metrics = self.evaluate_model(X_test, y_test)
        
        # Test on attack types
        attack_results = self.test_on_attack_types(df)
        
        # Print results
        self.print_evaluation_results(metrics)
        self.print_attack_type_results(attack_results)
        self.test_sample_packets()
        
        # Save report to file
        report_file = f"{PATHS['reports_dir']}/model_evaluation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        with open(report_file, 'w') as f:
            f.write("AI NETWORK SECURITY GUARD - MODEL EVALUATION REPORT\n")
            f.write("=" * 70 + "\n\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(f"Model: {self.model_path}\n")
            f.write(f"Test Samples: {len(X_test)}\n\n")
            
            f.write("OVERALL METRICS:\n")
            f.write("-" * 70 + "\n")
            f.write(f"Accuracy:         {metrics['accuracy']:.4f}\n")
            f.write(f"Precision:        {metrics['precision']:.4f}\n")
            f.write(f"Recall:           {metrics['recall']:.4f}\n")
            f.write(f"F1-Score:         {metrics['f1_score']:.4f}\n")
            f.write(f"Detection Rate:   {metrics['detection_rate']:.4f}\n")
            f.write(f"False Alarm Rate: {metrics['false_alarm_rate']:.4f}\n\n")
            
            f.write("ATTACK TYPE DETECTION RATES:\n")
            f.write("-" * 70 + "\n")
            for attack_type, stats in sorted(attack_results.items(), key=lambda x: x[1]['detection_rate'], reverse=True):
                f.write(f"{attack_type:<25}: {stats['detection_rate']*100:>6.2f}% ({stats['detected']}/{stats['total']})\n")
        
        logger.info(f"📄 Report saved to: {report_file}")
        print(f"\n📄 Full report saved to: {report_file}")


def main():
    """Run model evaluation"""
    print("=" * 70)
    print("🛡️  AI NETWORK SECURITY GUARD - MODEL EVALUATION")
    print("=" * 70)
    print()
    
    try:
        evaluator = ModelEvaluator()
        evaluator.generate_evaluation_report()
        
        print("\n✅ Evaluation complete!")
        
    except Exception as e:
        logger.error(f"❌ Evaluation failed: {e}")
        print(f"\n❌ Evaluation failed: {e}")


if __name__ == "__main__":
    main()
