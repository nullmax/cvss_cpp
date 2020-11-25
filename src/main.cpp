#include <iostream>
#include <list>
#include "cvss/cvss.h"

using namespace std;
using namespace ns3;

int main()
{
    CVSS m_cvss(CVSSMetricAV::Local, CVSSMetricAC::Low, CVSSMetricPRCIA::High, CVSSMetricUI::Required,
                                CVSSMetricS::Unchanged, CVSSMetricPRCIA::High, CVSSMetricPRCIA::None, CVSSMetricPRCIA::High,
                                CVSSMetricE::High, CVSSMetricRL::Workaround, CVSSMetricRC::Unknown,
                                CVSSMetricCIAR::High, CVSSMetricCIAR::High, CVSSMetricCIAR::Medium,
                                CVSSMetricAV::Local, CVSSMetricAC::Low, CVSSMetricPRCIA::High, CVSSMetricUI::None,
                                CVSSMetricS::Changed, CVSSMetricPRCIA::None, CVSSMetricPRCIA::High, CVSSMetricPRCIA::Low);
                                
    double scores[3];
    m_cvss.CalcScore(scores);
    for (int i = 0; i < 3; i++)
    {
        cout<<scores[i]<<endl;
    }
}