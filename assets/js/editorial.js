const activeFile=location.pathname.split('/').pop()||'index.html';
const navItems=[['Work','projects.html','blue'],['Journal','blog.html','green'],['Photographs','photography.html','orange'],['About','about.html','purple']];
const shell=document.querySelector('[data-masthead]');
if(shell){shell.innerHTML='<a class="skip-link" href="#main">Skip to content</a><nav class="nav-frame" aria-label="Main navigation"><a class="nav-brand" href="index.html">Brandon Sweat</a>'+navItems.map(([label,url,color])=>'<a class="nav-direct tone-'+color+'" href="'+url+'" '+((activeFile===url||(label==='About'&&activeFile==='resume.html'))?'aria-current="page"':'')+'>'+label+'<span aria-hidden="true">↗</span></a>').join('')+'</nav>';addEventListener('scroll',()=>shell.classList.toggle('scrolled',scrollY>36),{passive:true});}
const footer=document.querySelector('[data-footer]');if(footer)footer.innerHTML=`<div class="footer-bottom"><span>© ${new Date().getFullYear()} Brandon Sweat / Southern Utah</span><div class="footer-actions"><a href="mailto:brandonsweat@proton.me">Email ↗</a><a href="resume.html">Résumé ↗</a></div></div>`;
function magneticCards(){} // Compatibility for retained content renderers.
// Keep modal readers within keyboard reach without exposing the page behind them.
document.addEventListener('keydown',event=>{
 if(event.key!=='Tab')return;
 const dialog=document.querySelector('.article-overlay.open, .lightbox.open');
 if(!dialog)return;
 const controls=[...dialog.querySelectorAll('a[href],button,input,select,textarea,[tabindex="0"]')].filter(el=>el.getClientRects().length);
 if(!controls.length){event.preventDefault();dialog.focus();return}
 const first=controls[0],last=controls[controls.length-1];
 if(event.shiftKey&&(document.activeElement===first||!dialog.contains(document.activeElement))){event.preventDefault();last.focus()}
 else if(!event.shiftKey&&(document.activeElement===last||!dialog.contains(document.activeElement))){event.preventDefault();first.focus()}
});
