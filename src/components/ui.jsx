import React from 'react';
import { motion } from 'motion/react';

export function MetricCard({label,value,sub,icon:Icon,tone='mint',delta}) {
  return <motion.article className={'metric metric-'+tone} initial={{opacity:0,y:8}} animate={{opacity:1,y:0}} transition={{duration:.28}}>
    <div className="metric-head"><span>{label}</span>{Icon&&<span className="metric-icon"><Icon size={16}/></span>}</div>
    <div className="metric-number">{Number(value||0).toLocaleString()}</div>
    <div className="metric-foot"><span>{sub}</span>{delta&&<em>{delta}</em>}</div>
  </motion.article>;
}
export function SectionHeading({eyebrow,title,description,action}) {
  return <div className="panel-head"><div>{eyebrow&&<span className="overline">{eyebrow}</span>}<h2>{title}</h2>{description&&<p>{description}</p>}</div>{action}</div>;
}
export function StatusBadge({children,tone='neutral'}) {
  return <span className={'status-badge status-'+tone}>{children}</span>;
}
export function Surface({as:Component='section',className='',children,...props}) {
  return <Component className={['panel',className].filter(Boolean).join(' ')} {...props}>{children}</Component>;
}
